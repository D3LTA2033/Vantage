use std::collections::HashMap;
use vantage_core::{Error, Result};

#[derive(Debug, Clone, Copy)]
pub struct Spec {
    pub name: &'static str,
    pub value: bool,
    pub repeat: bool,
}

pub const fn flag(name: &'static str) -> Spec {
    Spec {
        name,
        value: false,
        repeat: false,
    }
}

pub const fn opt(name: &'static str) -> Spec {
    Spec {
        name,
        value: true,
        repeat: false,
    }
}

pub const fn multi(name: &'static str) -> Spec {
    Spec {
        name,
        value: true,
        repeat: true,
    }
}

#[derive(Debug, Default)]
pub struct Parsed {
    values: HashMap<&'static str, Vec<String>>,
    pub positional: Vec<String>,
    pub rest: Vec<String>,
}

impl Parsed {
    pub fn flag(&self, name: &str) -> bool {
        self.values.contains_key(name)
    }

    pub fn value(&self, name: &str) -> Option<&str> {
        self.values
            .get(name)
            .and_then(|v| v.last())
            .map(String::as_str)
    }

    pub fn values(&self, name: &str) -> &[String] {
        self.values.get(name).map_or(&[], Vec::as_slice)
    }

    pub fn parse_value<T: std::str::FromStr>(&self, name: &str) -> Result<Option<T>> {
        match self.value(name) {
            None => Ok(None),
            Some(v) => v
                .parse()
                .map(Some)
                .map_err(|_| Error::usage(format!("--{name}: invalid value {v:?}"))),
        }
    }
}

pub fn parse(args: &[String], specs: &[Spec], max_positional: usize) -> Result<Parsed> {
    let mut out = Parsed::default();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if a == "--" {
            out.rest = args[i..].to_vec();
            break;
        }
        if let Some(body) = a.strip_prefix("--") {
            let (name, inline) = match body.split_once('=') {
                Some((n, v)) => (n, Some(v.to_owned())),
                None => (body, None),
            };
            let spec = specs
                .iter()
                .find(|s| s.name == name)
                .ok_or_else(|| Error::usage(format!("unknown option --{name}")))?;
            let value = if spec.value {
                match inline {
                    Some(v) => v,
                    None => {
                        let v = args
                            .get(i)
                            .ok_or_else(|| Error::usage(format!("--{name} needs a value")))?
                            .clone();
                        i += 1;
                        v
                    }
                }
            } else {
                if inline.is_some() {
                    return Err(Error::usage(format!("--{name} takes no value")));
                }
                String::new()
            };
            let slot = out.values.entry(spec.name).or_default();
            if !spec.repeat && !slot.is_empty() && spec.value {
                return Err(Error::usage(format!("--{name} given more than once")));
            }
            slot.push(value);
            continue;
        }
        if a.starts_with('-') && a.len() > 1 {
            return Err(Error::usage(format!("unknown option {a}")));
        }
        if out.positional.len() >= max_positional {
            return Err(Error::usage(format!("unexpected argument {a:?}")));
        }
        out.positional.push(a.clone());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    const SPECS: &[Spec] = &[flag("json"), opt("pid"), multi("dir")];

    #[test]
    fn parses_forms() {
        let p = parse(
            &v(&[
                "--json", "--pid=5", "--dir", "/a", "--dir=/b", "file", "--", "ls", "--json",
            ]),
            SPECS,
            1,
        )
        .unwrap();
        assert!(p.flag("json"));
        assert_eq!(p.parse_value::<u32>("pid").unwrap(), Some(5));
        assert_eq!(p.values("dir"), &["/a", "/b"]);
        assert_eq!(p.positional, vec!["file"]);
        assert_eq!(p.rest, vec!["ls", "--json"]);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse(&v(&["--nope"]), SPECS, 0).is_err());
        assert!(parse(&v(&["--pid"]), SPECS, 0).is_err());
        assert!(parse(&v(&["--json=1"]), SPECS, 0).is_err());
        assert!(parse(&v(&["--pid", "1", "--pid", "2"]), SPECS, 0).is_err());
        assert!(parse(&v(&["a", "b"]), SPECS, 1).is_err());
        assert!(parse(&v(&["-x"]), SPECS, 1).is_err());
        assert!(
            parse(&v(&["--pid", "x"]), SPECS, 0)
                .unwrap()
                .parse_value::<u32>("pid")
                .is_err()
        );
    }
}
