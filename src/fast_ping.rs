use crate::dns::NameServerConfigGroup;
use crate::infra::ping::ping;

pub trait NameServerHealthyCheck {
    fn remove_timeout(&mut self);
}

impl NameServerHealthyCheck for NameServerConfigGroup {
    fn remove_timeout(&mut self) {
        let mut removed_idx = vec![];
        for (idx, ns) in self.iter().enumerate() {
            if ping(&ns.socket_addr, 1, 3000).is_none() {
                removed_idx.push(idx);
            }
        }

        while let Some(idx) = removed_idx.pop() {
            self.remove(idx);
        }
    }
}

#[cfg(test)]
mod tests {

    fn test() {}
}
