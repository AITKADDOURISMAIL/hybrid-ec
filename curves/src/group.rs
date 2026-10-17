//! Minimal group interface shared by the secp256k1 and Ed25519 point types.
pub trait Group: Copy {
    fn identity() -> Self;
    fn add(&self, o: &Self) -> Self;
    fn double(&self) -> Self;
    fn neg(&self) -> Self;
    fn select(a: &Self, b: &Self, choice: u64) -> Self;
}
impl Group for crate::secp256k1::Point {
    fn identity() -> Self { Self::IDENTITY }
    fn add(&self, o: &Self) -> Self { crate::secp256k1::Point::add(self, o) }
    fn double(&self) -> Self { crate::secp256k1::Point::double(self) }
    fn neg(&self) -> Self { crate::secp256k1::Point::neg(self) }
    fn select(a: &Self, b: &Self, c: u64) -> Self { crate::secp256k1::Point::select(a, b, c) }
}
impl Group for crate::ed25519::Point {
    fn identity() -> Self { Self::IDENTITY }
    fn add(&self, o: &Self) -> Self { crate::ed25519::Point::add(self, o) }
    fn double(&self) -> Self { crate::ed25519::Point::double(self) }
    fn neg(&self) -> Self { crate::ed25519::Point::neg(self) }
    fn select(a: &Self, b: &Self, c: u64) -> Self { crate::ed25519::Point::select(a, b, c) }
}
