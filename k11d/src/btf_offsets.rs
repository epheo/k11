//! Kernel struct field offsets from /sys/kernel/btf/vmlinux.
//!
//! The LSM hook addresses `struct file` by offset (`k11_common::KERNEL_FIELDS`);
//! `f_path` and `f_flags` move across kernel versions, so they are read from
//! BTF at startup and handed to the probe as .rodata. A field the running
//! kernel lacks leaves the LSM layer off rather than failing.

use std::collections::{HashMap, HashSet};
use std::fs;

use anyhow::{bail, Context, Result};
use k11_common::{KERNEL_FIELDS, KOFF_COUNT};

pub struct KernelOffsets {
    pub values: [u32; KOFF_COUNT],
    found: [bool; KOFF_COUNT],
}

impl KernelOffsets {
    /// True when every `struct file` offset the LSM hook needs was found.
    pub fn lsm_ready(&self) -> bool {
        self.found.iter().all(|&f| f)
    }

    /// "struct.field" for each field this kernel's BTF lacks.
    pub fn missing(&self) -> Vec<String> {
        KERNEL_FIELDS
            .iter()
            .filter(|(i, _, _)| !self.found[*i])
            .map(|(_, s, f)| format!("{s}.{f}"))
            .collect()
    }
}

pub fn discover() -> Result<KernelOffsets> {
    let data = fs::read("/sys/kernel/btf/vmlinux")
        .context("no /sys/kernel/btf/vmlinux: kernel built without CONFIG_DEBUG_INFO_BTF")?;
    let targets: HashSet<&str> = KERNEL_FIELDS.iter().map(|(_, s, _)| *s).collect();
    let structs = parse_btf_structs(&data, &targets)?;

    let mut offsets = KernelOffsets {
        values: [0; KOFF_COUNT],
        found: [false; KOFF_COUNT],
    };
    for (index, struct_name, field) in KERNEL_FIELDS {
        if let Some(offset) = lookup_field(&structs, struct_name, field) {
            offsets.values[index] = offset;
            offsets.found[index] = true;
        }
    }
    Ok(offsets)
}

type Members = Vec<(String, u32)>;

fn lookup_field(structs: &HashMap<String, Members>, struct_name: &str, field: &str) -> Option<u32> {
    structs
        .get(struct_name)?
        .iter()
        .find(|(name, _)| name == field)
        .map(|(_, offset)| *offset)
}

// --- BTF parser ---

const BTF_KIND_INT: u32 = 1;
const BTF_KIND_ARRAY: u32 = 3;
const BTF_KIND_STRUCT: u32 = 4;
const BTF_KIND_UNION: u32 = 5;
const BTF_KIND_ENUM: u32 = 6;
const BTF_KIND_FUNC_PROTO: u32 = 13;
const BTF_KIND_VAR: u32 = 14;
const BTF_KIND_DATASEC: u32 = 15;
const BTF_KIND_DECL_TAG: u32 = 17;
const BTF_KIND_ENUM64: u32 = 19;

struct RawMember {
    name: String,
    type_id: u32,
    byte_offset: u32,
}

/// Flatten the named target structs, inlining anonymous struct/union
/// members: `struct file` keeps `f_path` inside an anonymous union and
/// `struct qstr` keeps `len` inside one.
fn parse_btf_structs(data: &[u8], targets: &HashSet<&str>) -> Result<HashMap<String, Members>> {
    if data.len() < 24 {
        bail!("BTF data too short");
    }
    let u32_at = |off: usize| u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
    let hdr_len = u32_at(4) as usize;
    let type_off = u32_at(8) as usize;
    let type_len = u32_at(12) as usize;
    let str_off = u32_at(16) as usize;
    let str_len = u32_at(20) as usize;

    let strings = &data[hdr_len + str_off..hdr_len + str_off + str_len];
    let types = &data[hdr_len + type_off..hdr_len + type_off + type_len];
    let u32_in = |off: usize| u32::from_le_bytes(types[off..off + 4].try_into().unwrap());

    // Pass 1: every struct/union by type id, plus the ids of the targets.
    // The first struct with a target name wins; vmlinux defines each once.
    let mut all_types: HashMap<u32, Vec<RawMember>> = HashMap::new();
    let mut target_ids: HashMap<String, u32> = HashMap::new();

    let mut pos = 0;
    let mut tid: u32 = 1;
    while pos + 12 <= types.len() {
        let name_off = u32_in(pos);
        let info = u32_in(pos + 4);
        let kind = (info >> 24) & 0x1f;
        let vlen = (info & 0xffff) as usize;
        let kind_flag = info >> 31;

        if kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION {
            let mut members = Vec::with_capacity(vlen);
            for i in 0..vlen {
                let m = pos + 12 + i * 12;
                if m + 12 > types.len() {
                    break;
                }
                let bit_offset = u32_in(m + 8);
                // With kind_flag set the high byte holds a bitfield size.
                let bit_offset = if kind_flag != 0 {
                    bit_offset & 0xff_ffff
                } else {
                    bit_offset
                };
                members.push(RawMember {
                    name: btf_string(strings, u32_in(m)),
                    type_id: u32_in(m + 4),
                    byte_offset: bit_offset / 8,
                });
            }
            if kind == BTF_KIND_STRUCT {
                let name = btf_string(strings, name_off);
                if targets.contains(name.as_str()) {
                    target_ids.entry(name).or_insert(tid);
                }
            }
            all_types.insert(tid, members);
        }

        pos += 12
            + match kind {
                BTF_KIND_STRUCT | BTF_KIND_UNION | BTF_KIND_DATASEC | BTF_KIND_ENUM64 => vlen * 12,
                BTF_KIND_INT | BTF_KIND_VAR | BTF_KIND_DECL_TAG => 4,
                BTF_KIND_ARRAY => 12,
                BTF_KIND_ENUM | BTF_KIND_FUNC_PROTO => vlen * 8,
                _ => 0,
            };
        tid += 1;
    }

    // Pass 2: flatten each target.
    Ok(target_ids
        .into_iter()
        .map(|(name, tid)| {
            let mut fields = Vec::new();
            flatten_members(&all_types, tid, 0, &mut fields);
            (name, fields)
        })
        .collect())
}

fn flatten_members(all: &HashMap<u32, Vec<RawMember>>, type_id: u32, base: u32, out: &mut Members) {
    let Some(members) = all.get(&type_id) else {
        return;
    };
    for m in members {
        let offset = base + m.byte_offset;
        if m.name.is_empty() {
            flatten_members(all, m.type_id, offset, out);
        } else {
            out.push((m.name.clone(), offset));
        }
    }
}

fn btf_string(strings: &[u8], offset: u32) -> String {
    let start = offset as usize;
    if start >= strings.len() {
        return String::new();
    }
    let end = strings[start..]
        .iter()
        .position(|&b| b == 0)
        .map_or(strings.len(), |p| start + p);
    String::from_utf8_lossy(&strings[start..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use k11_common::{KOFF_FILE_F_FLAGS, KOFF_FILE_F_PATH};

    #[test]
    fn discover_from_live_kernel() {
        if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
            return;
        }
        let Ok(offsets) = discover() else { return }; // unreadable in some sandboxes
        assert!(offsets.lsm_ready(), "missing: {:?}", offsets.missing());
        let v = &offsets.values;
        assert!(v[KOFF_FILE_F_PATH] > 0 && v[KOFF_FILE_F_PATH] < 256);
        assert_ne!(v[KOFF_FILE_F_PATH], v[KOFF_FILE_F_FLAGS]);
    }
}
