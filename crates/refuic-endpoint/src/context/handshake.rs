pub struct HandshakeContextRfc9000 {}

impl HandshakeContextRfc9000 {
    // フラグで管理せずに条件を確認して返す
    // こうすることで、フラグの管理が煩雑になりバグが発生するのを防ぐ
    pub fn after_done(&self) -> bool {
        false
    }
}
