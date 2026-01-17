use std::io::{self, Write};
use k256::ecdsa::{SigningKey, VerifyingKey, Signature};
use k256::ecdsa::signature::{Signer, Verifier as OtherVerifier};
use rand_core::OsRng;
use sha2::{Sha256, Digest};
use std::collections::HashMap;

/// Represents a signature over the user's age commitment
struct Credential {
    signature: Signature,
    age_commitment: Vec<u8>,
}

/// The issuer holds a key pair
struct Issuer {
    sk: SigningKey,
    pk: VerifyingKey,
}

impl Issuer {
    fn new() -> Self {
        let sk = SigningKey::random(&mut OsRng);
        let pk = sk.verifying_key().clone();
        Self { sk, pk }
    }

    fn issue(&self, user: &User) -> Credential {
        let age_commitment = user.age_commitment();
        let sig = self.sk.sign(&age_commitment);

        Credential {
            signature: sig,
            age_commitment,
        }
    }
}

/// The user holds a secret and attributes
struct User {
    secret: Vec<u8>,
    attributes: HashMap<String, String>,
}

impl User {
    fn new(attrs: &[(&str, &str)]) -> Self {
        let secret = b"user-secret-randomness".to_vec();
        let attributes = attrs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        Self { secret, attributes }
    }

    /// H(secret || age)
    fn age_commitment(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&self.secret);
        hasher.update(self.attributes["age"].as_bytes());
        hasher.finalize().to_vec()
    }

    fn age(&self) -> u8 {
        self.attributes["age"].parse().unwrap()
    }

    fn prove_age_over_18<'a>(&'a self, cred: &'a Credential) -> AgeProof<'a> {
        AgeProof {
            signature: &cred.signature,
            age_commitment: cred.age_commitment.clone(),
            age: self.age(),
            secret: self.secret.clone(), // reveal for verification
        }
    }
}

/// Proof of age ≥ 18
struct AgeProof<'a> {
    signature: &'a Signature,
    age_commitment: Vec<u8>,
    age: u8,
    secret: Vec<u8>,
}

/// Verifier checks the proof
struct Verifier;

impl Verifier {
    fn verify_age_over_18(pk: &VerifyingKey, proof: &AgeProof) -> bool {
        // 1. Verify issuer signature on age commitment
        let sig_ok = pk
            .verify(&proof.age_commitment, proof.signature)
            .is_ok();

        // 2. Recompute commitment = H(secret || age)
        let mut hasher = Sha256::new();
        hasher.update(&proof.secret);
        hasher.update(proof.age.to_string().as_bytes());
        let recomputed = hasher.finalize().to_vec();

        let commitment_ok = recomputed == proof.age_commitment;

        // 3. Verify predicate
        let age_ok = proof.age >= 18;

        sig_ok && commitment_ok && age_ok
    }
}

fn main() {
    let issuer = Issuer::new();

    print!("Enter your age: ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();

    let age_str = input.trim(); // FIX: normalize input

    let _age: u8 = age_str
        .parse()
        .expect("Please enter a valid number");

    let user = User::new(&[
        ("age", age_str), // FIX: no newline mismatch
        ("citizen", "CM"),
        ("name", "Alice"),
    ]);

    let credential = issuer.issue(&user);

    let proof = user.prove_age_over_18(&credential);

    let ok = Verifier::verify_age_over_18(&issuer.pk, &proof);

    if ok {
        println!("User is over 18 and credential is valid: {}", ok);
    } else {
        println!("User is not over 18!");
    }
}


#[cfg(test)]
mod benches {
    use super::*;
    use criterion::{Criterion, criterion_group, criterion_main};

    pub fn age_proof_benchmark(c: &mut Criterion) {
        let issuer = Issuer::new();
        let user = User::new(&[
            ("age", "20"),
            ("citizen", "CM"),
            ("name", "Alice"),
        ]);

        let cred = issuer.issue(&user);

        c.bench_function("ECDSA verify age ≥ 18 proof", |b| {
            b.iter(|| {
                let proof = user.prove_age_over_18(&cred);
                Verifier::verify_age_over_18(&issuer.pk, &proof)
            });
        });
    }

    criterion_group!(benches, age_proof_benchmark);
    criterion_main!(benches);
}

