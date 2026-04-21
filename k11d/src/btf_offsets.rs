//! Discover kernel struct field offsets from /sys/kernel/btf/vmlinux at runtime.
//!
//! The file_open LSM hook receives a `struct file *`. The offset of `f_path`
//! within it varies across kernel versions, so we read it from BTF at startup
//! and pass it to the BPF program via a .rodata global.

use std::collections::HashMap;
use std::fs;

use anyhow::{bail, Context, Result};

/// Kernel struct field offsets needed by LSM BPF programs.
pub struct BtfOffsets {
    pub file_f_path: u32,
}

pub fn discover_offsets() -> Result<BtfOffsets> {
    let data = fs::read("/sys/kernel/btf/vmlinux")
        .context("failed to read /sys/kernel/btf/vmlinux — is the kernel built with CONFIG_DEBUG_INFO_BTF?")?;

    let structs = parse_btf_structs(&data)?;

    Ok(BtfOffsets {
        file_f_path: lookup_field(&structs, "file", "f_path")?,
    })
}

fn lookup_field(
    structs: &HashMap<String, Vec<(String, u32)>>,
    struct_name: &str,
    field_name: &str,
) -> Result<u32> {
    let members = structs
        .get(struct_name)
        .with_context(|| format!("struct {struct_name} not found in kernel BTF"))?;
    members
        .iter()
        .find(|(name, _)| name == field_name)
        .map(|(_, offset)| *offset)
        .with_context(|| {
            let available: Vec<_> = members.iter().map(|(n, _)| n.as_str()).collect();
            format!("field '{field_name}' not found in struct {struct_name} (available: {available:?})")
        })
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

/// Raw member before anonymous-member resolution.
struct RawMember {
    name: String,
    type_id: u32,
    byte_offset: u32,
}

/// Parsed struct/union with raw members.
struct RawType {
    #[allow(dead_code)]
    kind: u32,
    members: Vec<RawMember>,
}

/// Parse BTF and extract struct fields, flattening anonymous union/struct members.
///
/// Anonymous members (empty name) in structs are common in the Linux kernel.
/// For example, `struct file` has `f_path` inside an anonymous union at offset 64.
/// We recursively inline these so `lookup_field("file", "f_path")` works.
fn parse_btf_structs(data: &[u8]) -> Result<HashMap<String, Vec<(String, u32)>>> {
    if data.len() < 24 {
        bail!("BTF data too short");
    }

    let hdr_len = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
    let type_off = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
    let type_len = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;
    let str_off = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
    let str_len = u32::from_le_bytes(data[20..24].try_into().unwrap()) as usize;

    let strings = &data[hdr_len + str_off..hdr_len + str_off + str_len];
    let types_data = &data[hdr_len + type_off..hdr_len + type_off + type_len];

    let targets = ["file"];

    // Pass 1: collect all struct/union types by type_id (needed to resolve anonymous members).
    let mut all_types: HashMap<u32, RawType> = HashMap::new();
    // Also collect name → type_id for target structs.
    let mut target_ids: HashMap<String, u32> = HashMap::new();

    let mut pos = 0;
    let mut tid: u32 = 1;
    while pos + 12 <= types_data.len() {
        let name_off = u32::from_le_bytes(types_data[pos..pos + 4].try_into().unwrap());
        let info = u32::from_le_bytes(types_data[pos + 4..pos + 8].try_into().unwrap());
        let kind = (info >> 24) & 0x1f;
        let vlen = (info & 0xffff) as usize;
        let k_flag = info >> 31;

        if kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION {
            let mut members = Vec::new();
            for i in 0..vlen {
                let m_off = pos + 12 + i * 12;
                if m_off + 12 > types_data.len() {
                    break;
                }
                let m_name_off =
                    u32::from_le_bytes(types_data[m_off..m_off + 4].try_into().unwrap());
                let m_type_id =
                    u32::from_le_bytes(types_data[m_off + 4..m_off + 8].try_into().unwrap());
                let m_bit_offset =
                    u32::from_le_bytes(types_data[m_off + 8..m_off + 12].try_into().unwrap());
                let bit_offset = if k_flag != 0 {
                    m_bit_offset & 0xFFFFFF
                } else {
                    m_bit_offset
                };
                members.push(RawMember {
                    name: btf_string(strings, m_name_off),
                    type_id: m_type_id,
                    byte_offset: bit_offset / 8,
                });
            }

            if kind == BTF_KIND_STRUCT {
                let name = btf_string(strings, name_off);
                if targets.contains(&name.as_str()) {
                    target_ids.insert(name, tid);
                }
            }

            all_types.insert(tid, RawType { kind, members });
        }

        // Advance position based on kind
        match kind {
            BTF_KIND_STRUCT | BTF_KIND_UNION => pos += 12 + vlen * 12,
            BTF_KIND_INT | BTF_KIND_VAR => pos += 12 + 4,
            BTF_KIND_ARRAY => pos += 12 + 12,
            BTF_KIND_ENUM => pos += 12 + vlen * 8,
            BTF_KIND_FUNC_PROTO => pos += 12 + vlen * 8,
            BTF_KIND_DATASEC => pos += 12 + vlen * 12,
            BTF_KIND_DECL_TAG => pos += 12 + 4,
            BTF_KIND_ENUM64 => pos += 12 + vlen * 12,
            _ => pos += 12,
        }
        tid += 1;
    }

    // Pass 2: for each target struct, flatten anonymous members recursively.
    let mut result: HashMap<String, Vec<(String, u32)>> = HashMap::new();
    for (name, tid) in &target_ids {
        let mut fields = Vec::new();
        flatten_members(&all_types, *tid, 0, &mut fields);
        result.insert(name.clone(), fields);
    }

    Ok(result)
}

/// Recursively flatten struct/union members, inlining anonymous members.
/// `base_offset` accumulates parent offsets for nested anonymous types.
fn flatten_members(
    all_types: &HashMap<u32, RawType>,
    type_id: u32,
    base_offset: u32,
    out: &mut Vec<(String, u32)>,
) {
    let raw = match all_types.get(&type_id) {
        Some(t) => t,
        None => return,
    };
    for member in &raw.members {
        let offset = base_offset + member.byte_offset;
        if member.name.is_empty() {
            // Anonymous member — recurse into its type to inline fields.
            flatten_members(all_types, member.type_id, offset, out);
        } else {
            out.push((member.name.clone(), offset));
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
        .map(|p| start + p)
        .unwrap_or(strings.len());
    String::from_utf8_lossy(&strings[start..end]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_offsets_from_live_kernel() {
        if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
            return;
        }
        let offsets = discover_offsets().expect("BTF offset discovery failed");
        assert!(offsets.file_f_path > 0 && offsets.file_f_path < 256);
    }
}
