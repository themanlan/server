use std::fs;
use std::collections::HashSet;

pub struct Blocklist {
    domains: HashSet<String>,
}

impl Blocklist {
    /// Reads a file with one domain per line.
    pub fn load(path: &str) -> Self {
        match fs::read_to_string(path) {
            Ok(text) => Self::parse(&text),
            Err(e) => {
                eprintln!("could not read path {path}: {e}");
                Self { domains: HashSet::new()}
            }
        }
    }

    fn parse(text: &str) -> Self {
        let domains = text.lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty() && !l.starts_with('#'))
                        .map(str::to_lowercase)
                        .collect();
                    Self { domains }
    }

    pub fn len(&self) -> usize {
        self.domains.len()
    }

    //Blocks the name and anything underneath it
    pub fn is_blocked(&self, name: &str) -> bool {
        let mut candidate = name;
        loop {
            if self.domains.contains(candidate) {
                return true;
            }
            match candidate.split_once('.') {
                Some((_,rest)) => candidate = rest,
                None => return false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_subdomains_but_not_lookalikes() {
        let list = Blocklist::parse("# comment\ndoubleclick.net\n");
        assert!(list.is_blocked("doubleclick.net"));
        assert!(list.is_blocked("ad.x.doubleclick.net"));
        assert!(!list.is_blocked("notdoubleclick.net"));
        assert!(!list.is_blocked("example.com"));
    }
}
