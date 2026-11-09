//! Authenticated denial of existence: NSEC3, the TTL of a proof, iteration limits, compact denial, and the captured
//! denials.

mod nsec3 {
    //! RFC 5155 §5 (the NSEC3 hash) against the hashes of Appendix A and B, §2 (algorithm 7 is RSASHA1's alias, with
    //! the 512-bit key of Appendix A that D71 refuses), and the denials of §8 against the responses of Appendix B.

    use data_encoding::BASE32HEX_NOPAD;
    use dedens_dnssec::crypto::{
        Budget, UnsupportedNsec3Hash, VerifyError, key_tag, nsec3_hash, verify,
    };
    use dedens_dnssec::denial::{self, Fact, MaxIterations, Proof, Unproven};
    use dedens_proto::{Nsec3HashAlgorithm, Question, Record, RecordType, SecAlgorithm, Ttl};
    use dedens_testkit::dnssec::{Rr, Rrsig, b64, canonical_name, dnskey_rdata, signed_data};
    use dedens_testkit::zone;

    use crate::util::denial::{nsec3_salted, nsec3_with, pick, prove, prove_wildcard};
    use crate::util::name;

    const SALT: [u8; 4] = [0xaa, 0xbb, 0xcc, 0xdd];
    const ITERATIONS: u16 = 12;

    /// Appendix A, "The zone is preceded by a list that contains the hashes of the original ownernames", then
    /// the hashes Appendix B prints.
    const HASHES: [(&str, &str); 16] = [
        ("example.", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"),
        ("a.example.", "35mthgpgcu1qg68fab165klnsnk3dpvl"),
        ("ai.example.", "gjeqe526plbf1g8mklp59enfd789njgi"),
        ("ns1.example.", "2t7b4g4vsa5smi47k61mv5bv1a22bojr"),
        ("ns2.example.", "q04jkcevqvmu85r014c7dkba38o0ji5r"),
        ("w.example.", "k8udemvp1j2f7eg6jebps17vp3n8i58h"),
        ("*.w.example.", "r53bq7cc2uvmubfu5ocmm6pers9tk9en"),
        ("x.w.example.", "b4um86eghhds6nea196smvmlo4ors995"),
        ("y.w.example.", "ji6neoaepv8b5o6k4ev33abha8ht9fgc"),
        ("x.y.w.example.", "2vptu5timamqttgl4luu9kg21e0aor3s"),
        ("xx.example.", "t644ebqk9bibcna874givr6joj62mlhv"),
        (
            "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.",
            "kohar7mbb8dc2ce8a9qvl8hon4k53uhi",
        ),
        ("c.x.w.example.", "0va5bpr2ou0vk0lbqeeljri88laipsfh"),
        ("*.x.w.example.", "92pqneegtaue7pjatc3l3qnk738c6v5m"),
        ("c.example.", "4g6p9u5gvfshp30pqecj98b3maqbn1ck"),
        ("z.w.example.", "qlu7gtfaeh0ek0c05ksfhdpbcgglbe03"),
    ];

    // Appendix A: the zone's 512-bit ZSK, key tag 40430, and its RRSIG over the SOA `RRset`.
    const ZSK: &str = "AwEAAaetidLzsKWUt4swWR8yu0wPHPiUi8LU
    sAD0QPWU+wzt89epO6tHzkMBVDkC7qphQO2h
    TY4hHn9npWFRw5BYubE=";

    fn hashed(owner: &str, iterations: u16) -> String {
        let hash =
            nsec3_hash(Nsec3HashAlgorithm::SHA1, &SALT, iterations, &name(owner)).expect("SHA-1");
        BASE32HEX_NOPAD.encode(&hash).to_ascii_lowercase()
    }

    #[test]
    fn hashes_are_the_rfcs() {
        for (owner, hash) in HASHES {
            assert_eq!(hashed(owner, ITERATIONS), hash, "{owner}");
        }
    }

    #[test]
    fn the_owner_is_hashed_in_lower_case() {
        // §5: the owner is in canonical form (RFC 4034 §6.2).
        assert_eq!(
            hashed("A.EXAMPLE.", ITERATIONS),
            "35mthgpgcu1qg68fab165klnsnk3dpvl"
        );
        assert_eq!(
            hashed("X.W.Example.", ITERATIONS),
            "b4um86eghhds6nea196smvmlo4ors995"
        );
    }

    #[test]
    fn the_count_and_the_salt_change_the_hash() {
        // The vectors pin 12 iterations and the salt; other values must not give the same hash.
        let owner = name("example.");
        let twelve = nsec3_hash(Nsec3HashAlgorithm::SHA1, &SALT, 12, &owner).expect("SHA-1");
        let zero = nsec3_hash(Nsec3HashAlgorithm::SHA1, &SALT, 0, &owner).expect("SHA-1");
        let empty_salt = nsec3_hash(Nsec3HashAlgorithm::SHA1, &[], 12, &owner).expect("SHA-1");
        assert_ne!(twelve, zero);
        assert_ne!(twelve, empty_salt);
        assert_eq!(
            BASE32HEX_NOPAD.encode(&twelve).to_ascii_lowercase(),
            "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"
        );
    }

    #[test]
    fn the_maximum_count_is_computed() {
        // RFC 9276 §3.2 is the caller's policy: the hash still takes 65536 rounds and ends.
        let _ = nsec3_hash(Nsec3HashAlgorithm::SHA1, &SALT, u16::MAX, &name("example."))
            .expect("SHA-1");
    }

    #[test]
    fn algorithms_other_than_sha1_are_unsupported() {
        for code in 0..=u8::MAX {
            if code == 1 {
                continue;
            }
            let algorithm = Nsec3HashAlgorithm(code);
            assert_eq!(
                nsec3_hash(algorithm, &SALT, ITERATIONS, &name("example.")),
                Err(UnsupportedNsec3Hash(algorithm))
            );
        }
    }

    #[test]
    fn the_512_bit_zone_key_of_appendix_a_is_unusable() {
        // §2: algorithm 7 is RSASHA1 for NSEC3 zones; RFC 3110 allows 512 bits, D71 starts at 1024.
        let rdata = dnskey_rdata(256, 7, ZSK);
        assert_eq!(key_tag(&rdata), 40430);
        let rrsig = Rrsig {
            type_covered: 6,
            algorithm: 7,
            labels: 1,
            original_ttl: 3600,
            expiration: 1_429_574_399,
            inception: 1_129_852_800,
            key_tag: 40430,
            signer: "example.",
        };
        // `example. 3600 IN SOA ns1.example. bugs.x.w.example. 1 3600 300 3600000 3600`.
        let mut soa = canonical_name("ns1.example.");
        soa.extend(canonical_name("bugs.x.w.example."));
        for field in [1_u32, 3600, 300, 3_600_000, 3600] {
            soa.extend(field.to_be_bytes());
        }
        let signed = signed_data(
            &rrsig,
            &[Rr {
                owner: "example.",
                rdata: soa,
            }],
        );
        let signature = b64("Hu25UIyNPmvPIVBrldN+9Mlp9Zql39qaUd8i
         q4ZLlYWfUUbbAS41pG+68z81q1xhkYAcEyHd
         VI2LmKusbZsT0Q==");
        assert_eq!(
            verify(
                SecAlgorithm::RSASHA1_NSEC3_SHA1,
                &b64(ZSK),
                &signed,
                &signature
            ),
            Err(VerifyError::UnusableKey)
        );
    }

    // The denials of §8 and Appendix B, from the NSEC3 records of Appendix A, `testdata/zones`.

    const APEX: &str = "example.";
    /// The TTL of every record of Appendix A.
    const TTL: Ttl = Ttl::from_wire(3600);
    const NAME_ERROR: Fact = Fact::NameError { compact: false };

    // The hashes of Appendix A, by the name they are of.
    const EXAMPLE: &str = "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom";
    const NS1: &str = "2t7b4g4vsa5smi47k61mv5bv1a22bojr";
    const A: &str = "35mthgpgcu1qg68fab165klnsnk3dpvl";
    const X_W: &str = "b4um86eghhds6nea196smvmlo4ors995";
    const Y_W: &str = "ji6neoaepv8b5o6k4ev33abha8ht9fgc";
    const W: &str = "k8udemvp1j2f7eg6jebps17vp3n8i58h";
    const NS2: &str = "q04jkcevqvmu85r014c7dkba38o0ji5r";
    const WILDCARD_W: &str = "r53bq7cc2uvmubfu5ocmm6pers9tk9en";

    fn nsec3s(hashes: &[&str]) -> Vec<Record<'static>> {
        let owners: Vec<String> = hashes.iter().map(|h| format!("{h}.example.")).collect();
        let owners: Vec<&str> = owners.iter().map(String::as_str).collect();
        pick(&zone("rfc5155_appendix_a.zone"), RecordType::NSEC3, &owners)
    }

    /// A proof of `fact` over a covered next closer name, whose record has the opt-out flag (all of Appendix A do).
    fn proof(fact: Fact) -> Proof {
        Proof {
            fact,
            ttl: TTL,
            opt_out: true,
        }
    }

    /// A proof by a record that matches the name: no span is involved, so no opt-out.
    fn matched(fact: Fact) -> Proof {
        Proof {
            opt_out: false,
            ..proof(fact)
        }
    }

    /// B.1: `x.w.example.` is the closest encloser of `a.c.x.w.example.`, `c.x.w.example.` is covered by the apex's
    /// record and `*.x.w.example.` by `a.example.`'s.
    #[test]
    fn b1_name_error() {
        let records = nsec3s(&[EXAMPLE, X_W, A]);
        assert_eq!(
            prove(APEX, "a.c.x.w.example.", RecordType::A, &records),
            Ok(proof(NAME_ERROR))
        );
        // Each of the three is needed.
        assert_eq!(
            prove(
                APEX,
                "a.c.x.w.example.",
                RecordType::A,
                &nsec3s(&[EXAMPLE, X_W])
            ),
            Err(Unproven::WildcardNotDenied)
        );
        assert_eq!(
            prove(APEX, "a.c.x.w.example.", RecordType::A, &nsec3s(&[X_W, A])),
            Err(Unproven::NoClosestEncloser)
        );
        assert_eq!(
            prove(
                APEX,
                "a.c.x.w.example.",
                RecordType::A,
                &nsec3s(&[EXAMPLE, A])
            ),
            Err(Unproven::NoClosestEncloser)
        );
    }

    /// B.2: `ns1.example.` exists and has no MX; B.2.1: `y.w.example.` is an empty non-terminal, no data as well.
    #[test]
    fn b2_no_data() {
        assert_eq!(
            prove(APEX, "ns1.example.", RecordType::MX, &nsec3s(&[NS1])),
            Ok(matched(Fact::NoData))
        );
        assert_eq!(
            prove(APEX, "ns1.example.", RecordType::A, &nsec3s(&[NS1])),
            Err(Unproven::TypePresent)
        );
        assert_eq!(
            prove(APEX, "y.w.example.", RecordType::A, &nsec3s(&[Y_W])),
            Ok(matched(Fact::NoData))
        );
    }

    /// B.3: the referral to `c.example.` is to an unsigned zone: the closest provable encloser of `c.example.` is
    /// `example.`, and the record that covers `c.example.` has the opt-out flag.
    #[test]
    fn b3_referral_to_opt_out_zone() {
        let records = nsec3s(&[A, EXAMPLE]);
        assert_eq!(
            prove(APEX, "c.example.", RecordType::DS, &records),
            Ok(proof(Fact::InsecureDelegation))
        );
        // Derived: without the flag (rewritten on the real records) nothing says `c.example.` has no signed zone.
        let records: Vec<_> = records
            .iter()
            .map(|r| nsec3_with(r, Nsec3HashAlgorithm::SHA1, 0, ITERATIONS))
            .collect();
        assert_eq!(
            prove(APEX, "c.example.", RecordType::DS, &records),
            Err(Unproven::WildcardNotDenied)
        );
    }

    /// B.4: the RRSIG of `a.z.w.example.` has 2 labels, and `z.w.example.` is covered by `ns2`'s record.
    #[test]
    fn b4_wildcard_expansion() {
        assert_eq!(
            prove_wildcard(APEX, "a.z.w.example.", 2, &nsec3s(&[NS2])),
            Ok(proof(Fact::WildcardAnswer))
        );
        // `w.example.` exists: with 3 labels the next closer name is `a.z.w.example.`, covered by nothing here.
        assert_eq!(
            prove_wildcard(APEX, "a.z.w.example.", 3, &nsec3s(&[NS2])),
            Err(Unproven::NotCovered)
        );
        // `x.w.example.` exists.
        assert_eq!(
            prove_wildcard(APEX, "a.x.w.example.", 2, &nsec3s(&[X_W])),
            Err(Unproven::CloserNameExists)
        );
    }

    /// B.5: `w.example.` is the closest encloser, `*.w.example.` exists with MX only.
    #[test]
    fn b5_wildcard_no_data() {
        let records = nsec3s(&[W, NS2, WILDCARD_W]);
        assert_eq!(
            prove(APEX, "a.z.w.example.", RecordType::AAAA, &records),
            Ok(proof(Fact::WildcardNoData))
        );
        assert_eq!(
            prove(APEX, "a.z.w.example.", RecordType::MX, &records),
            Err(Unproven::WildcardHasType)
        );
    }

    /// B.6: the record of `example.` has SOA, so it comes from the child zone, not the delegation.
    #[test]
    fn b6_ds_from_the_child() {
        assert_eq!(
            prove(APEX, "example.", RecordType::DS, &nsec3s(&[EXAMPLE])),
            Err(Unproven::FromChildApex)
        );
    }

    /// §8.1, §8.2: records of an unknown hash algorithm or with flags other than 0 and 1 are ignored. Derived:
    /// the algorithm and flags of the real records of Appendix A are rewritten.
    #[test]
    fn unusable_records_are_ignored() {
        let records = nsec3s(&[EXAMPLE, X_W, A]);
        let unknown: Vec<_> = records
            .iter()
            .map(|r| nsec3_with(r, Nsec3HashAlgorithm(2), 1, ITERATIONS))
            .collect();
        assert_eq!(
            prove(APEX, "a.c.x.w.example.", RecordType::A, &unknown),
            Err(Unproven::NoUsableRecords)
        );
        let flags: Vec<_> = records
            .iter()
            .map(|r| nsec3_with(r, Nsec3HashAlgorithm::SHA1, 2, ITERATIONS))
            .collect();
        assert_eq!(
            prove(APEX, "a.c.x.w.example.", RecordType::A, &flags),
            Err(Unproven::NoUsableRecords)
        );
        // A record of another chain that the proof does not use.
        let mut mixed = records.clone();
        mixed.push(nsec3_with(
            &records[0],
            Nsec3HashAlgorithm(2),
            1,
            ITERATIONS,
        ));
        assert_eq!(
            prove(APEX, "a.c.x.w.example.", RecordType::A, &mixed),
            Ok(proof(NAME_ERROR))
        );
    }

    /// §8.3, RFC 6840 §4.1: `a.example.` has NS and no SOA, so no name below it is in the zone: it is no closest
    /// encloser, though its record matches an ancestor and covers `x.a.example.`.
    #[test]
    fn closest_encloser_is_not_a_delegation() {
        assert_eq!(
            prove(APEX, "x.a.example.", RecordType::A, &nsec3s(&[A])),
            Err(Unproven::EncloserBelowCut)
        );
    }

    /// §8.2: records of more than one set of parameters are not one zone's: nothing is proven, and the caller makes
    /// the response bogus, whichever record comes first. Derived: the iterations and the salt of one real record of
    /// Appendix A are rewritten.
    #[test]
    fn records_of_two_sets_of_parameters_prove_nothing() {
        let records = nsec3s(&[EXAMPLE, X_W, A]);
        for other in [
            nsec3_with(&records[2], Nsec3HashAlgorithm::SHA1, 1, ITERATIONS + 1),
            nsec3_salted(&records[2], &[0xaa, 0xbb]),
        ] {
            let mut mixed = records[..2].to_vec();
            mixed.push(other.clone());
            let mut reversed = vec![other];
            reversed.extend_from_slice(&records[..2]);
            for set in [mixed, reversed] {
                assert_eq!(
                    prove(APEX, "a.c.x.w.example.", RecordType::A, &set),
                    Err(Unproven::ConflictingNsec3Parameters)
                );
            }
        }
    }

    /// §9.2: the proof over a next closer name that an opt-out record covers says so: the name may be an insecure
    /// delegation, and the answer is not authenticated. The mark is the covering record's own: the flag of the other
    /// records does not change it. Derived: the flags of real records of Appendix A are rewritten.
    #[test]
    fn opt_out_comes_from_the_record_that_covers_the_next_closer_name() {
        let flags = |flags: [u8; 3]| -> Vec<Record<'static>> {
            nsec3s(&[EXAMPLE, X_W, A])
                .iter()
                .zip(flags)
                .map(|(r, flags)| nsec3_with(r, Nsec3HashAlgorithm::SHA1, flags, ITERATIONS))
                .collect()
        };
        // `c.x.w.example.` is covered by the record of the apex, the first.
        let name_error =
            |set: Vec<Record<'static>>| prove(APEX, "a.c.x.w.example.", RecordType::A, &set);
        assert_eq!(name_error(flags([1, 0, 0])), Ok(proof(NAME_ERROR)));
        let closed = name_error(flags([0, 1, 1])).expect("a proof");
        assert_eq!(closed.fact, NAME_ERROR);
        assert!(!closed.opt_out);
        // Wildcard no data: `a.z.w.example.`, `z.w.example.` covered by the record of `ns2.example.`.
        let records = nsec3s(&[W, NS2, WILDCARD_W]);
        let flagged = |flag| -> Vec<Record<'static>> {
            records
                .iter()
                .enumerate()
                .map(|(i, r)| {
                    nsec3_with(
                        r,
                        Nsec3HashAlgorithm::SHA1,
                        u8::from(i == 1) * flag,
                        ITERATIONS,
                    )
                })
                .collect()
        };
        assert_eq!(
            prove(APEX, "a.z.w.example.", RecordType::AAAA, &flagged(1)),
            Ok(proof(Fact::WildcardNoData))
        );
        let closed = prove(APEX, "a.z.w.example.", RecordType::AAAA, &flagged(0)).expect("a proof");
        assert!(!closed.opt_out);
        // Wildcard answer: the same record.
        assert_eq!(
            prove_wildcard(APEX, "a.z.w.example.", 2, &flagged(1)),
            Ok(proof(Fact::WildcardAnswer))
        );
        let closed = prove_wildcard(APEX, "a.z.w.example.", 2, &flagged(0)).expect("a proof");
        assert!(!closed.opt_out);
    }

    /// §8.6: a DS question whose next closer name is in an opt-out span is an insecure delegation, ahead of the
    /// wildcard that the same records deny: the answer is a referral, and it is marked opt-out.
    #[test]
    fn a_ds_question_under_opt_out_is_an_insecure_delegation() {
        let records = nsec3s(&[EXAMPLE, X_W, A]);
        assert_eq!(
            prove(APEX, "a.c.x.w.example.", RecordType::DS, &records),
            Ok(proof(Fact::InsecureDelegation))
        );
        // Not in a span with the flag, it is a name error as for any type.
        let closed: Vec<_> = records
            .iter()
            .map(|r| nsec3_with(r, Nsec3HashAlgorithm::SHA1, 0, ITERATIONS))
            .collect();
        let closed = prove(APEX, "a.c.x.w.example.", RecordType::DS, &closed).expect("a proof");
        assert_eq!(closed.fact, NAME_ERROR);
        assert!(!closed.opt_out);
    }

    /// §5: each of the `iterations + 1` hashes is SHA-1 of its input and the salt, and a SHA-1 block holds 55 octets
    /// of message: a salt of 255 octets makes each one 5 blocks, where no salt makes it 1. The `Budget` counts
    /// blocks (D106), so the proof of `a.c.x.w.example.` (5 hashes at 150 iterations) costs 5 times as much with the
    /// long salt. Derived: Appendix A's records, their iterations and salt rewritten (the hashes no longer match, so
    /// the proof ends at the closest encloser).
    #[test]
    fn a_long_salt_costs_the_blocks_it_makes() {
        let spent = |salt: &[u8]| {
            let records: Vec<_> = nsec3s(&[EXAMPLE, X_W, A])
                .iter()
                .map(|r| nsec3_salted(&nsec3_with(r, Nsec3HashAlgorithm::SHA1, 0, 150), salt))
                .collect();
            let mut budget = Budget::default();
            let before = budget.nsec3_blocks_left().0;
            let question = Question::new(name("a.c.x.w.example."), RecordType::A);
            let proof = denial::prove(
                &name(APEX),
                &question,
                &records,
                MaxIterations::default(),
                &mut budget,
            );
            assert_eq!(proof, Err(Unproven::NoClosestEncloser));
            before - budget.nsec3_blocks_left().0
        };
        let none = spent(&[]);
        let long = spent(&[0x5a; 255]);
        assert_eq!(none, 5 * 151);
        assert_eq!(long, 5 * (5 + 150 * 5));
        assert!(long >= 4 * none, "{long} against {none}");
    }
}

mod ttl {
    //! RFC 9077 §3: a negative proof is cached as long as the shortest of the records it used. The records are those
    //! of the RFC 4035 and RFC 5155 example zones, with their TTLs changed (derived: the RFCs give one TTL to all).

    use dedens_dnssec::denial::Fact;
    use dedens_proto::{Record, RecordType, Ttl};
    use dedens_testkit::zone;

    use crate::util::denial::{pick, prove, prove_wildcard};

    const APEX: &str = "example.";

    fn with_ttls(mut records: Vec<Record<'static>>, ttls: &[u32]) -> Vec<Record<'static>> {
        for (record, ttl) in records.iter_mut().zip(ttls) {
            record.ttl = Ttl::from_wire(*ttl);
        }
        records
    }

    fn nsecs(owners: &[&str]) -> Vec<Record<'static>> {
        pick(&zone("rfc4035_appendix_a.zone"), RecordType::NSEC, owners)
    }

    fn nsec3s(hashes: &[&str]) -> Vec<Record<'static>> {
        let owners: Vec<String> = hashes.iter().map(|h| format!("{h}.example.")).collect();
        let owners: Vec<&str> = owners.iter().map(String::as_str).collect();
        pick(&zone("rfc5155_appendix_a.zone"), RecordType::NSEC3, &owners)
    }

    #[test]
    fn nsec_proof_lasts_as_long_as_its_shortest_record() {
        let mut records = with_ttls(nsecs(&["b.example.", "example."]), &[300, 60]);
        // A record the proof does not use does not count.
        records.extend(with_ttls(nsecs(&["xx.example."]), &[0]));
        let proof = prove(APEX, "ml.example.", RecordType::A, &records).expect("a proof");
        assert_eq!(proof.fact, Fact::NameError { compact: false });
        assert_eq!(proof.ttl, Ttl::from_wire(60));
    }

    #[test]
    fn nsec3_proof_lasts_as_long_as_its_shortest_record() {
        // The closest encloser, the next closer name's record and the wildcard's.
        let records = with_ttls(
            nsec3s(&[
                "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
                "b4um86eghhds6nea196smvmlo4ors995",
                "35mthgpgcu1qg68fab165klnsnk3dpvl",
            ]),
            &[300, 60, 600],
        );
        let proof = prove(APEX, "a.c.x.w.example.", RecordType::A, &records).expect("a proof");
        assert_eq!(proof.ttl, Ttl::from_wire(60));
    }

    #[test]
    fn a_wildcard_answer_lasts_as_long_as_its_covering_record() {
        let records = with_ttls(nsec3s(&["q04jkcevqvmu85r014c7dkba38o0ji5r"]), &[120]);
        let proof = prove_wildcard(APEX, "a.z.w.example.", 2, &records).expect("a proof");
        assert_eq!(proof.fact, Fact::WildcardAnswer);
        assert_eq!(proof.ttl, Ttl::from_wire(120));
    }
}

mod iterations {
    //! RFC 9276 §3.2: NSEC3 records above the iteration limit prove nothing and the response is insecure, with EDE 27
    //! (in the registry of RFC 8914 §5.2); the hashing they ask for is counted by the `Budget`.

    use dedens_dnssec::crypto::{Budget, BudgetExhausted, Nsec3Blocks, Verifications};
    use dedens_dnssec::denial::{self, MaxIterations, Unproven};
    use dedens_proto::edns::InfoCode;
    use dedens_proto::{Nsec3HashAlgorithm, Question, RecordType};
    use dedens_testkit::dnssec::response;
    use dedens_testkit::zone;

    use crate::util::denial::{nsec3_with, pick, prove};

    /// The captured NSEC3 name error of `nonexistent-xyz123.dev.`: 1 iteration.
    fn iterating() -> (Question<'static>, Vec<dedens_proto::Record<'static>>) {
        let message = response("nxdomain_nsec3_iterations");
        let question = message.questions[0].clone();
        let records = message
            .authority
            .into_iter()
            .filter(|r| r.rtype() == RecordType::NSEC3)
            .collect();
        (question, records)
    }

    fn apex() -> dedens_proto::Name<'static> {
        "dev.".parse().expect("a name")
    }

    fn prove_with(max: MaxIterations, budget: &mut Budget) -> Result<denial::Proof, Unproven> {
        let (question, records) = iterating();
        denial::prove(&apex(), &question, &records, max, budget)
    }

    /// The capture has 1 iteration: a limit of 1 accepts it, a limit of 0 does not.
    #[test]
    fn the_limit_is_inclusive() {
        let accepted = prove_with(MaxIterations(1), &mut Budget::default()).expect("a proof");
        assert_eq!(accepted.fact, denial::Fact::NameError { compact: false });
        assert_eq!(
            prove_with(MaxIterations(0), &mut Budget::default()),
            Err(Unproven::IterationsAboveLimit {
                iterations: 1,
                limit: 0
            })
        );
    }

    /// The default limit is 150, as in Unbound and BIND (D74): the NSEC3 records of RFC 5155 with 150 iterations are
    /// looked at, and with 151 they are not. Derived: the iteration count of a real record of RFC 5155 Appendix A
    /// (`2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.`) is rewritten; no capture has more than one iteration.
    #[test]
    fn the_default_limit_is_150() {
        assert_eq!(MaxIterations::default(), MaxIterations(150));
        let zone = zone("rfc5155_appendix_a.zone");
        let nsec3 = pick(
            &zone,
            RecordType::NSEC3,
            &["2t7b4g4vsa5smi47k61mv5bv1a22bojr.example."],
        );
        let with = |iterations| -> Vec<_> {
            nsec3
                .iter()
                .map(|r| nsec3_with(r, Nsec3HashAlgorithm::SHA1, 1, iterations))
                .collect()
        };
        // The hash no longer matches: the records are used, and prove nothing of this name.
        assert_eq!(
            prove("example.", "ns1.example.", RecordType::MX, &with(150)),
            Err(Unproven::NoClosestEncloser)
        );
        let above = prove("example.", "ns1.example.", RecordType::MX, &with(151));
        assert_eq!(
            above,
            Err(Unproven::IterationsAboveLimit {
                iterations: 151,
                limit: 150
            })
        );
        assert_eq!(
            above.expect_err("above").info_code(),
            Some(InfoCode::UNSUPPORTED_NSEC3_ITERATIONS)
        );
        // The maximum a record can say is refused all the same.
        assert!(matches!(
            prove("example.", "ns1.example.", RecordType::MX, &with(u16::MAX)),
            Err(Unproven::IterationsAboveLimit { .. })
        ));
    }

    /// §3.2: a response whose hashing does not fit the budget is refused, and the budget says which counter ran out;
    /// the verdict, insecure or SERVFAIL, is the caller's (D71). The budget counts SHA-1 blocks (D106).
    #[test]
    fn hashing_is_counted_by_the_budget() {
        // One hash of 1 iteration, of a short name and a short salt, is 2 computations of one block: it costs 2.
        let mut budget = Budget::new(Verifications(0), Nsec3Blocks(1));
        assert_eq!(
            prove_with(MaxIterations(1), &mut budget),
            Err(Unproven::Budget(BudgetExhausted::Nsec3Blocks))
        );
        assert_eq!(budget.nsec3_blocks_left(), Nsec3Blocks(0));
        // The budget the proof leaves is the one it did not spend.
        let mut budget = Budget::default();
        let before = budget.nsec3_blocks_left().0;
        prove_with(MaxIterations(1), &mut budget).expect("a proof");
        let spent = before - budget.nsec3_blocks_left().0;
        assert!(spent > 0 && spent % 2 == 0, "{spent}");
    }

    /// RFC 5155 B.1 (`a.c.x.w.example.`, 12 iterations, so 13 blocks a hash) takes four hashes: the name, its parent,
    /// the closest encloser and its wildcard. The budget runs out in the loop that looks for the closest encloser,
    /// or at the wildcard, and a budget of the whole cost, 52 blocks, is enough.
    #[test]
    fn the_budget_runs_out_in_the_middle_of_a_proof() {
        let records = pick(
            &zone("rfc5155_appendix_a.zone"),
            RecordType::NSEC3,
            &[
                "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.",
                "b4um86eghhds6nea196smvmlo4ors995.example.",
                "35mthgpgcu1qg68fab165klnsnk3dpvl.example.",
            ],
        );
        let question = Question::new("a.c.x.w.example.".parse().expect("a name"), RecordType::A);
        let apex = "example.".parse().expect("a name");
        let run = |blocks| {
            let mut budget = Budget::new(Verifications(0), Nsec3Blocks(blocks));
            denial::prove(
                &apex,
                &question,
                &records,
                MaxIterations::default(),
                &mut budget,
            )
        };
        for short in [0, 12, 13, 26, 38, 39, 51] {
            assert_eq!(
                run(short),
                Err(Unproven::Budget(BudgetExhausted::Nsec3Blocks)),
                "{short}"
            );
        }
        assert!(run(52).is_ok());
    }

    /// The limit holds for every set of parameters in the response, not only the first one read.
    /// Derived: the iterations of real records of RFC 5155 Appendix A are rewritten.
    #[test]
    fn the_limit_applies_to_every_set_of_parameters() {
        let zone = zone("rfc5155_appendix_a.zone");
        let owners = [
            "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.",
            "35mthgpgcu1qg68fab165klnsnk3dpvl.example.",
        ];
        let nsec3 = pick(&zone, RecordType::NSEC3, &owners);
        let records = vec![
            nsec3_with(&nsec3[0], Nsec3HashAlgorithm::SHA1, 1, 12),
            nsec3_with(&nsec3[1], Nsec3HashAlgorithm::SHA1, 1, 151),
        ];
        assert_eq!(
            prove("example.", "ns1.example.", RecordType::MX, &records),
            Err(Unproven::IterationsAboveLimit {
                iterations: 151,
                limit: 150
            })
        );
    }
}

mod compact {
    //! RFC 9824 (compact denial of existence): an NSEC or NSEC3 with NXNAME in its bitmap, under NOERROR, proves a
    //! name error; one with the types of the name proves no data. The Cloudflare captures of `testdata/dnssec/` are the
    //! responses. A query for NXNAME itself is refused with EDE 30 (in the registry of RFC 8914 §5.2).

    use dedens_dnssec::crypto::Budget;
    use dedens_dnssec::denial::{self, Fact, MaxIterations, Unproven};
    use dedens_proto::edns::InfoCode;
    use dedens_proto::rdata::{Nsec3, RData, TypeBitmap};
    use dedens_proto::{Class, Message, Rcode, Record, RecordType};
    use dedens_testkit::dnssec::response;
    use dedens_testkit::zone;

    use crate::util::denial::{pick, prove};

    fn denials(message: &Message<'static>) -> Vec<Record<'static>> {
        message
            .authority
            .iter()
            .filter(|r| r.rtype() == RecordType::NSEC)
            .cloned()
            .collect()
    }

    /// §3.1, §3.3: the NOERROR response of `nonexistent.cloudflare.com.` has an NSEC at the name that lists NXNAME:
    /// the name does not exist, and 06 sees it was not an NXDOMAIN.
    #[test]
    fn nxname_is_a_name_error() {
        let message = response("nxname_cloudflare");
        assert_eq!(message.rcode(), Rcode::NOERROR);
        let proof = prove(
            "cloudflare.com.",
            "nonexistent.cloudflare.com.",
            RecordType::A,
            &denials(&message),
        )
        .expect("a proof");
        assert_eq!(proof.fact, Fact::NameError { compact: true });
        // Any type of the name gets the same: the name is not there.
        let proof = prove(
            "cloudflare.com.",
            "nonexistent.cloudflare.com.",
            RecordType::MX,
            &denials(&message),
        )
        .expect("a proof");
        assert_eq!(proof.fact, Fact::NameError { compact: true });
    }

    /// §3.2: the NSEC at `cloudflare.com.` lists its types, and no SRV: no data.
    #[test]
    fn compact_no_data_is_no_data() {
        let message = response("nodata_compact");
        let records = denials(&message);
        let proof = prove(
            "cloudflare.com.",
            "cloudflare.com.",
            RecordType::SRV,
            &records,
        )
        .expect("a proof");
        assert_eq!(proof.fact, Fact::NoData);
        assert_eq!(
            prove(
                "cloudflare.com.",
                "cloudflare.com.",
                RecordType::MX,
                &records
            ),
            Err(Unproven::TypePresent)
        );
    }

    /// §3.5, §9: NXNAME is not a type to answer: the question is refused with EDE 30 before any record is read.
    #[test]
    fn nxname_is_not_a_question() {
        let message = response("nxname_cloudflare");
        let refused = prove(
            "cloudflare.com.",
            "nonexistent.cloudflare.com.",
            RecordType::NXNAME,
            &denials(&message),
        );
        assert_eq!(refused, Err(Unproven::NxnameQuery));
        assert_eq!(
            refused.expect_err("refused").info_code(),
            Some(InfoCode::INVALID_QUERY_TYPE)
        );
    }

    /// Derived: §4: an NSEC3 at the hash of the name with NXNAME in its bitmap says the same as the NSEC. The record
    /// is the real one of `ns1.example.` in RFC 5155 Appendix A with its bitmap replaced; no capture has compact
    /// denial by NSEC3.
    #[test]
    fn nsec3_nxname_is_a_name_error() {
        let zone = zone("rfc5155_appendix_a.zone");
        let records: Vec<_> = pick(
            &zone,
            RecordType::NSEC3,
            &["2t7b4g4vsa5smi47k61mv5bv1a22bojr.example."],
        )
        .iter()
        .map(|r| {
            let RData::Nsec3(n) = r.data() else {
                panic!("an NSEC3 record");
            };
            let types = TypeBitmap::from_types([RecordType::NXNAME, RecordType::RRSIG]);
            let n = Nsec3::new(
                n.hash_algorithm,
                n.flags,
                n.iterations,
                n.salt(),
                n.next_hashed_owner(),
                types,
            )
            .expect("valid");
            Record::new(r.name.clone(), Class::IN, r.ttl, &RData::Nsec3(n))
        })
        .collect();
        let proof = denial::prove(
            &"example.".parse().expect("a name"),
            &dedens_proto::Question::new("ns1.example.".parse().expect("a name"), RecordType::A),
            &records,
            MaxIterations::default(),
            &mut Budget::default(),
        )
        .expect("a proof");
        assert_eq!(proof.fact, Fact::NameError { compact: true });
    }
}

mod captured {
    //! Every negative response of `testdata/dnssec/capture.yaml` (described in its `README.md`) proves what its rcode
    //! and question say: a name error, no data, a wildcard no data or an unsigned delegation, by NSEC or NSEC3 of
    //! any parameters, opt-out or not. The records are those of the response, whose signatures `rrsig::captured` and
    //! the validator check; here they are trusted.

    use std::fs;

    use dedens_dnssec::crypto::Budget;
    use dedens_dnssec::denial::{self, Fact, MaxIterations};
    use dedens_proto::rdata::RData;
    use dedens_proto::{Message, Name, Rcode, Record, RecordType, Ttl};
    use dedens_testkit::dnssec::response;

    use crate::util::denial::{prove, prove_wildcard};

    const NAME_ERROR: Fact = Fact::NameError { compact: false };
    const COMPACT_NAME_ERROR: Fact = Fact::NameError { compact: true };

    /// What each capture proves, by id, and whether the NSEC3 over its next closer name has the opt-out flag.
    const EXPECTED: [(&str, Fact, bool); 43] = [
        ("nxdomain_root_nsec", NAME_ERROR, false),
        ("nxdomain_nsec", NAME_ERROR, false),
        ("nxdomain_nsec3", NAME_ERROR, false),
        ("nxdomain_nsec3_optout", NAME_ERROR, true),
        ("nxdomain_nsec3_salt", NAME_ERROR, true),
        ("nxdomain_nsec3_iterations", NAME_ERROR, false),
        ("nxname_cloudflare", COMPACT_NAME_ERROR, false),
        ("nodata_compact", Fact::NoData, false),
        ("nodata_root_nsec", Fact::NoData, false),
        ("nodata_nsec", Fact::NoData, false),
        ("nodata_nsec3", Fact::NoData, false),
        ("nodata_nsec3_optout", Fact::NoData, false),
        ("nodata_nsec3_iterations", Fact::NoData, false),
        ("ent_nsec", Fact::NoData, false),
        ("ent_nsec3", Fact::NoData, false),
        ("wildcard_nodata", Fact::WildcardNoData, false),
        ("wildcard_nodata_nsec", Fact::WildcardNoData, false),
        ("wildcard_nodata_optout", Fact::WildcardNoData, true),
        ("google_com_ds", Fact::InsecureDelegation, true),
        ("jm_ds", Fact::InsecureDelegation, false),
        ("edgekey_net_ds", Fact::InsecureDelegation, true),
        ("akamaiedge_net_ds", Fact::InsecureDelegation, true),
        // The DS of each owner of an answer, which the chain of trust asks for.
        ("leaf_xyzzy_ds", NAME_ERROR, false),
        ("leaf_nxdomain_nlnetlabs_ds", NAME_ERROR, false),
        ("leaf_nxdomain_debian_ds", NAME_ERROR, false),
        ("leaf_nxdomain_dev_ds", NAME_ERROR, false),
        ("leaf_nxname_cloudflare_ds", COMPACT_NAME_ERROR, false),
        ("leaf_ent_nlnetlabs_ds", Fact::NoData, false),
        ("leaf_ent_sidnlabs_ds", Fact::NoData, false),
        ("leaf_wildcard_sidnlabs_ds", Fact::WildcardNoData, false),
        ("leaf_wildcard_internet_nl_ds", Fact::WildcardNoData, false),
        ("leaf_synthesized_nist_gov_ds", Fact::NoData, false),
        ("leaf_wildcard_ph_ds", Fact::InsecureDelegation, true),
        ("leaf_wildcard_ws_ds", Fact::InsecureDelegation, true),
        ("leaf_dname_sidnlabs_ds", Fact::NoData, false),
        ("leaf_www_example_nl_ds", Fact::NoData, false),
        ("leaf_cdn_cloudflare_net_ds", Fact::NoData, false),
        ("leaf_org_cdn_ds", Fact::NoData, false),
        ("leaf_www_nlnetlabs_ds", Fact::NoData, false),
        ("leaf_icann_cdn_ds", Fact::NoData, false),
        ("leaf_icann_cdn_mid_ds", Fact::NoData, false),
        ("leaf_sigok_ippacket_ds", Fact::NoData, false),
        ("leaf_sigfail_ippacket_ds", Fact::NoData, false),
    ];

    /// The captured responses that are not in [`EXPECTED`]: the wildcard expansion is tested below; the DS of a name
    /// under an opt-out span is an NXDOMAIN with the proof of an insecure delegation, and a referral's DS is proven for
    /// the child, not for the name asked.
    const OTHERS: [&str; 4] = [
        "wildcard_answer",
        "leaf_nxdomain_com_ds",
        "leaf_nxdomain_org_ds",
        "referral_unsigned",
    ];

    fn is_denial(record: &Record<'_>) -> bool {
        matches!(record.rtype(), RecordType::NSEC | RecordType::NSEC3)
    }

    /// The zone that signed the denial: the signer of the RRSIGs over its NSEC or NSEC3 records.
    fn apex(message: &Message<'static>) -> Name<'static> {
        message
            .authority
            .iter()
            .find_map(|r| match r.data() {
                RData::Rrsig(rrsig)
                    if matches!(rrsig.type_covered, RecordType::NSEC | RecordType::NSEC3) =>
                {
                    Some(rrsig.signer.into_owned())
                }
                _ => None,
            })
            .expect("a signed denial")
    }

    /// The least TTL of the NSEC and NSEC3 records of the response: each capture's proof uses them all, and every
    /// record the proof reads has one of them or more.
    fn least_ttl(message: &Message<'_>) -> Ttl {
        message
            .authority
            .iter()
            .filter(|r| is_denial(r))
            .map(|r| r.ttl)
            .min()
            .expect("denial records")
    }

    #[test]
    fn every_negative_capture_proves_what_it_says() {
        for (id, fact, opt_out) in EXPECTED {
            let message = response(id);
            let question = &message.questions[0];
            let proof = prove(
                &apex(&message).to_string(),
                &question.name.to_string(),
                question.qtype,
                &message.authority,
            )
            .unwrap_or_else(|e| panic!("{id}: {e}"));
            assert_eq!(proof.fact, fact, "{id}");
            assert_eq!(proof.opt_out, opt_out, "{id}: opt-out");
            let rcode = if fact == NAME_ERROR {
                Rcode::NXDOMAIN
            } else {
                Rcode::NOERROR
            };
            assert_eq!(message.rcode(), rcode, "{id}");
            assert_eq!(proof.ttl, least_ttl(&message), "{id}");
        }
    }

    /// A new capture with a denial in it has to be added to the tables above.
    #[test]
    fn every_capture_with_a_denial_is_listed() {
        for entry in fs::read_dir(dedens_testkit::path("dnssec")).expect("testdata directory") {
            let path = entry.expect("entry").path();
            let Some(id) = path.extension().is_some_and(|e| e == "bin").then(|| {
                path.file_stem()
                    .expect("stem")
                    .to_string_lossy()
                    .into_owned()
            }) else {
                continue;
            };
            let message = response(&id);
            let negative = message.rcode() == Rcode::NXDOMAIN || message.answer.is_empty();
            if negative && message.authority.iter().any(is_denial) {
                assert!(
                    EXPECTED.iter().any(|(listed, ..)| *listed == id)
                        || OTHERS.contains(&id.as_str())
                        || id.starts_with("ip6_ds_"),
                    "{id} has a denial and is not listed"
                );
            }
        }
    }

    /// The DS of each label of an IPv6 reverse name, below `arpa`: a DS where a zone starts, else no data.
    #[test]
    fn the_ds_of_each_label_of_a_reverse_name_is_there_or_proven_absent() {
        for n in 1..=34 {
            let id = format!("ip6_ds_{n}");
            let message = response(&id);
            if !message.answer.is_empty() {
                continue;
            }
            let question = &message.questions[0];
            let proof = prove(
                &apex(&message).to_string(),
                &question.name.to_string(),
                question.qtype,
                &message.authority,
            )
            .unwrap_or_else(|e| panic!("{id}: {e}"));
            assert_eq!(proof.fact, Fact::NoData, "{id}");
        }
    }

    /// The answer's RRSIG has fewer labels than its owner, and the NSEC3 of the response covers the next closer name.
    #[test]
    fn wildcard_expansion_is_proven() {
        let message = response("wildcard_answer");
        let question = &message.questions[0];
        let labels = message
            .answer
            .iter()
            .find_map(|r| match r.data() {
                RData::Rrsig(rrsig) if rrsig.type_covered == question.qtype => Some(rrsig.labels),
                _ => None,
            })
            .expect("an RRSIG over the answer");
        let apex = apex(&message).to_string();
        let proof = prove_wildcard(
            &apex,
            &question.name.to_string(),
            labels,
            &message.authority,
        )
        .expect("a proof");
        assert_eq!(proof.fact, Fact::WildcardAnswer);
        assert_eq!(proof.ttl, least_ttl(&message));
        assert!(!proof.opt_out);
    }

    /// The proof of one capture needs about one hash per label of the name, three at most beside the question's: a few
    /// SHA-1 blocks, as many as the iterations make of each.
    #[test]
    fn proofs_cost_a_few_hashes() {
        let message = response("nxdomain_nsec3_iterations");
        let question = &message.questions[0];
        let mut budget = Budget::default();
        let before = budget.nsec3_blocks_left();
        denial::prove(
            &apex(&message),
            question,
            &message.authority,
            MaxIterations::default(),
            &mut budget,
        )
        .expect("a proof");
        let spent = before.0 - budget.nsec3_blocks_left().0;
        // One iteration: two blocks per hash; the name, its parent, the closest encloser's wildcard.
        assert!(spent > 0 && spent <= 3 * 2 * 3, "{spent}");
    }
}
