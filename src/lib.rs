//! A small `.netrc` parser, forked from netrc-rs 0.1.2.
//!
//! Lines whose first non-space character is `#` are comments, as in curl and
//! Python's `netrc` module. A `#` elsewhere on a line is kept, because it can be
//! part of a password.

use std::fmt;

/// One `machine` (or `default`) entry
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Machine {
    /// `None` for the `default` entry
    pub name: Option<String>,
    pub login: Option<String>,
    pub password: Option<String>,
    pub account: Option<String>,
}

impl Machine {
    fn credentials(&self) -> Option<(&str, &str)> {
        Some((self.login.as_deref()?, self.password.as_deref()?))
    }
}

/// A parsed netrc file
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Netrc {
    pub machines: Vec<Machine>,
}

/// A parse failure, with the 1-based line it happened on
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (line {})", self.message, self.line)
    }
}

impl std::error::Error for Error {}

impl Netrc {
    /// Parse netrc content.
    ///
    /// A `macdef` body runs until the next blank line and is ignored; comment
    /// lines inside it are part of the macro.
    pub fn parse(content: &str) -> Result<Netrc, Error> {
        let mut machines: Vec<Machine> = vec![];
        let mut in_macdef = false;
        // keyword waiting for its value, and the line it appeared on
        let mut pending: Option<(&str, usize)> = None;
        for (idx, line) in content.lines().enumerate() {
            let lineno = idx + 1;
            if in_macdef {
                in_macdef = !line.trim().is_empty();
                continue;
            }
            if line.trim_start().starts_with('#') {
                continue;
            }
            for tok in line.split_whitespace() {
                if let Some((key, _)) = pending.take() {
                    if key == "machine" {
                        machines.push(Machine {
                            name: Some(tok.to_string()),
                            ..Default::default()
                        });
                    } else if let Some(m) = machines.last_mut() {
                        let value = Some(tok.to_string());
                        match key {
                            "login" => m.login = value,
                            "password" => m.password = value,
                            _ => m.account = value,
                        }
                    }
                    continue;
                }
                match tok {
                    "machine" => pending = Some((tok, lineno)),
                    "login" | "password" | "account" => {
                        if machines.is_empty() {
                            return Err(Error {
                                line: lineno,
                                message: format!("{tok} must follow machine"),
                            });
                        }
                        pending = Some((tok, lineno));
                    }
                    "default" => machines.push(Machine::default()),
                    "macdef" => {
                        // the rest of the line is the macro name; the body follows
                        in_macdef = true;
                        break;
                    }
                    _ => {
                        return Err(Error {
                            line: lineno,
                            message: format!("unexpected token {tok:?}"),
                        });
                    }
                }
            }
        }
        match pending {
            Some((key, line)) => Err(Error {
                line,
                message: format!("missing value after {key}"),
            }),
            None => Ok(Netrc { machines }),
        }
    }

    /// Credentials for `host`: an exact (case-insensitive) `machine` match with
    /// both login and password, else the `default` entry.
    pub fn credentials(&self, host: &str) -> Option<(&str, &str)> {
        self.machines
            .iter()
            .find(|m| {
                m.name
                    .as_deref()
                    .is_some_and(|n| n.eq_ignore_ascii_case(host))
            })
            .and_then(Machine::credentials)
            .or_else(|| {
                self.machines
                    .iter()
                    .find(|m| m.name.is_none())
                    .and_then(Machine::credentials)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_comment_lines() {
        let content = "#stepsecurity-package-config-credential-dmg-begin
machine example.com
  # indented comment
  login user
  password pa#ss
#stepsecurity-package-config-credential-dmg-end
";
        let netrc = Netrc::parse(content).unwrap();
        assert_eq!(
            netrc.machines,
            vec![Machine {
                name: Some("example.com".into()),
                login: Some("user".into()),
                password: Some("pa#ss".into()),
                account: None,
            }]
        );
    }

    #[test]
    fn parses_one_line_form_default_and_account() {
        let netrc = Netrc::parse(
            "machine a.com login u1 password p1 account acct\ndefault login anon password guest",
        )
        .unwrap();
        assert_eq!(netrc.machines.len(), 2);
        assert_eq!(netrc.machines[0].account.as_deref(), Some("acct"));
        assert_eq!(netrc.credentials("A.com"), Some(("u1", "p1")));
        assert_eq!(netrc.credentials("other.com"), Some(("anon", "guest")));
    }

    #[test]
    fn macdef_ends_at_blank_line() {
        let netrc = Netrc::parse(
            "machine a.com login u password p\nmacdef init\n# in macro\ncd /pub\n\nmachine b.com login v password q\n",
        )
        .unwrap();
        assert_eq!(netrc.machines.len(), 2);
        assert_eq!(netrc.credentials("b.com"), Some(("v", "q")));
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(Netrc::parse("login u").unwrap_err().line, 1);
        assert!(Netrc::parse("machine a.com bogus").is_err());
        assert!(Netrc::parse("machine a.com login").is_err());
    }
}
