use hec_validation::{sign_for_tests, reduce_mod_l, sha512::sha512, verify, verify_batch, verify_batch_fast, verify_fast, Policy};
fn hx(s: &str) -> Vec<u8> {
    if s == "-" { return vec![]; }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}
struct Case { pk: [u8; 32], msg: Vec<u8>, sig: [u8; 64], pc: bool, ps: bool }
fn cases() -> Vec<Case> {
    include_str!("validation.txt").lines().map(|l| {
        let f: Vec<&str> = l.split(' ').collect();
        Case { pk: hx(f[0]).try_into().unwrap(), msg: hx(f[1]), sig: hx(f[2]).try_into().unwrap(), pc: f[3] == "1", ps: f[4] == "1" }
    }).collect()
}
#[test]
fn sha512_matches_hashlib() {
    for l in include_str!("sha512.txt").lines() {
        let f: Vec<&str> = l.split(' ').collect();
        assert_eq!(sha512(&[&hx(f[0])]).to_vec(), hx(f[1]), "sha512 {l}");
    }
}
#[test]
fn policies_match_python_oracle() {
    let (mut acc_c, mut acc_s, mut div) = (0, 0, 0);
    for c in cases() {
        let pc = verify(&c.pk, &c.msg, &c.sig, Policy::Cofactored);
        let ps = verify(&c.pk, &c.msg, &c.sig, Policy::Strict);
        assert_eq!(pc, c.pc, "P_c pk={:02x?}", &c.pk[..4]);
        assert_eq!(ps, c.ps, "P_s pk={:02x?}", &c.pk[..4]);
        acc_c += pc as u32; acc_s += ps as u32; div += (pc != ps) as u32;
    }
    assert!(acc_c > 50 && acc_s > 10 && div > 10, "{acc_c} {acc_s} {div}");
}
/// Batch result must equal the AND of the individual P_c verdicts (w.h.p., 128-bit z).
#[test]
fn batch_agrees_with_individual_cofactored() {
    let cs = cases();
    let mut seed = 12345u64;
    let mut rnd = || { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; seed };
    for round in 0..40 {
        let size = 1 + (rnd() % 6) as usize;
        // half the rounds favour accepted cases so that "true" batches occur
        let pool: Vec<&Case> = if round % 2 == 0 { cs.iter().filter(|c| c.pc).collect() } else { cs.iter().collect() };
        let picks: Vec<&Case> = (0..size).map(|_| pool[(rnd() % pool.len() as u64) as usize]).collect();
        let items: Vec<_> = picks.iter().map(|c| (c.pk, c.msg.clone(), c.sig)).collect();
        let z: Vec<[u8; 16]> = (0..size).map(|_| { let mut b = [0u8; 16]; b[..8].copy_from_slice(&rnd().to_le_bytes()); b[8..].copy_from_slice(&rnd().to_le_bytes()); b[0] |= 1; b }).collect();
        let want = picks.iter().all(|c| c.pc);
        assert_eq!(verify_batch(&items, &z), want, "round {round}");
        assert_eq!(verify_batch_fast(&items, &z), want, "fast round {round}");
    }
}

#[test]
fn fast_verify_matches_oracle_and_reference() {
    for c in cases() {
        for (pol, want) in [(Policy::Cofactored, c.pc), (Policy::Strict, c.ps)] {
            assert_eq!(verify_fast(&c.pk, &c.msg, &c.sig, pol), want, "fast {:?} pk={:02x?}", pol, &c.pk[..4]);
        }
    }
}
#[test]
fn reduce_mod_l_matches_python() {
    for l in include_str!("modl.txt").lines() {
        let f: Vec<&str> = l.split(' ').collect();
        let h: [u8; 64] = hx(f[0]).try_into().unwrap();
        assert_eq!(reduce_mod_l(&h).to_vec(), hx(f[1]), "modl {l}");
    }
}

/// Larger batches (up to 70 items, so that several window widths are exercised), valid and with one invalid item.
#[test]
fn batch_fast_large_batches() {
    let cs = cases();
    let good: Vec<&Case> = cs.iter().filter(|c| c.pc).collect();
    let bad: Vec<&Case> = cs.iter().filter(|c| !c.pc).collect();
    assert!(!bad.is_empty());
    let mut seed = 777u64;
    let mut rnd = || { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; seed };
    for &size in &[1usize, 2, 3, 5, 9, 17, 33, 70] {
        let mut picks: Vec<&Case> = (0..size).map(|_| good[(rnd() % good.len() as u64) as usize]).collect();
        let z: Vec<[u8; 16]> = (0..size).map(|_| { let mut b = [0u8; 16]; b[..8].copy_from_slice(&rnd().to_le_bytes()); b[8..].copy_from_slice(&rnd().to_le_bytes()); b[0] |= 1; b }).collect();
        let items: Vec<_> = picks.iter().map(|c| (c.pk, c.msg.clone(), c.sig)).collect();
        assert!(verify_batch_fast(&items, &z), "valid batch of {size}");
        let pos = (rnd() % size as u64) as usize;
        picks[pos] = bad[(rnd() % bad.len() as u64) as usize];
        let items: Vec<_> = picks.iter().map(|c| (c.pk, c.msg.clone(), c.sig)).collect();
        assert_eq!(verify_batch_fast(&items, &z), verify_batch(&items, &z), "mixed batch of {size}");
    }
}

#[test]
fn generated_signatures_verify_and_batch() {
    let mut items = Vec::new();
    for i in 0..40u8 {
        let seed = [i.wrapping_mul(7).wrapping_add(1); 32];
        let msg = vec![i; (i % 9) as usize + 1];
        let (pk, sig) = sign_for_tests(&seed, &msg);
        assert!(verify(&pk, &msg, &sig, Policy::Cofactored) && verify_fast(&pk, &msg, &sig, Policy::Strict), "sig {i}");
        items.push((pk, msg, sig));
    }
    let z: Vec<[u8; 16]> = (0..items.len()).map(|i| [i as u8 | 1; 16]).collect();
    assert!(verify_batch_fast(&items, &z));
    items[7].1.push(0);
    assert!(!verify_batch_fast(&items, &z));
}
