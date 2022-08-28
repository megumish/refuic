use refuic_packet::long::initial::ClientInitialPacket;

pub struct InitialContextRfc9000 {}

impl InitialContextRfc9000 {
    // フラグで管理せずに条件を確認して返す
    // こうすることで、フラグの管理が煩雑になりバグが発生するのを防ぐ
    pub fn after_hello(&self) -> bool {
        false
    }

    pub fn from_client_initial(p: &ClientInitialPacket) -> Self {
        Self {}
    }
}
