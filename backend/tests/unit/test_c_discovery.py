"""Phase 10: focused C discovery tests (RSA/AES/SHA/ECDSA/ECDH/Ed25519/EVP)."""

from ecdat.discovery.rule_loader import load_rules
from ecdat.discovery.source_scanner import scan_file
from ecdat.engines.evidence_engine import process_file_result

RULES = load_rules()


def _scan_c(code: str):
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "probe.c"
        target.write_text(code)
        file_result = scan_file(target, RULES, relative_to=Path(tmp))
        assert file_result is not None
        return [
            ev.asset for ev in
            process_file_result(file_result=file_result, relative_to=Path(tmp))
        ]


def _by_rule(assets, rule_id):
    return [a for a in assets if a.evidence.rule_id == rule_id]


def test_rsa_api_detected() -> None:
    assets = _scan_c(
        "int f(RSA *r) {\n"
        "  RSA_generate_key_ex(r, 2048, NULL, NULL);\n"
        "  RSA_public_encrypt(1, a, b, r, 1);\n"
        "  RSA_sign(1, a, 1, b, NULL, r);\n"
        "  return 0;\n}\n"
    )
    assert _by_rule(assets, "R-330")
    assert _by_rule(assets, "R-332")
    assert _by_rule(assets, "R-334")
    keygen = _by_rule(assets, "R-330")[0]
    assert keygen.algorithm == "RSA"
    assert keygen.purpose.value == "key_establishment"
    sign = _by_rule(assets, "R-334")[0]
    assert sign.purpose.value == "digital_signature"


def test_aes_gcm_api_detected() -> None:
    assets = _scan_c(
        "void f(void) {\n"
        "  const EVP_CIPHER *c = EVP_aes_256_gcm();\n"
        "  EVP_EncryptInit_ex(NULL, c, NULL, NULL, NULL);\n"
        "}\n"
    )
    assert _by_rule(assets, "R-362")
    assert _by_rule(assets, "R-365")
    fetch = _by_rule(assets, "R-362")[0]
    assert fetch.algorithm == "AES-256-GCM"
    assert fetch.purpose.value == "encryption"
    assert fetch.evidence.observed_symbol == "EVP_aes_256_gcm"


def test_sha256_api_detected() -> None:
    assets = _scan_c(
        "void f(void) {\n"
        "  const EVP_MD *m = EVP_sha256();\n"
        "  SHA256_Init(NULL);\n"
        "}\n"
    )
    assert _by_rule(assets, "R-372")
    assert _by_rule(assets, "R-380")
    assert _by_rule(assets, "R-372")[0].algorithm == "SHA-256"


def test_ecdsa_api_detected() -> None:
    assets = _scan_c(
        "int f(EC_KEY *k) {\n"
        "  EC_KEY_generate_key(k);\n"
        "  ECDSA_sign(0, d, 1, s, NULL, k);\n"
        "  return 0;\n}\n"
    )
    assert _by_rule(assets, "R-342")
    assert _by_rule(assets, "R-343")
    assert _by_rule(assets, "R-342")[0].purpose.value == "key_establishment"
    assert _by_rule(assets, "R-343")[0].purpose.value == "digital_signature"


def test_ecdh_api_detected() -> None:
    assets = _scan_c(
        "int f(EC_KEY *k) {\n"
        "  return ECDH_compute_key(NULL, 0, NULL, k, NULL);\n"
        "}\n"
    )
    assert _by_rule(assets, "R-345")
    ecdh = _by_rule(assets, "R-345")[0]
    assert ecdh.algorithm == "ECDH"
    assert ecdh.purpose.value == "key_establishment"


def test_ed25519_nid_detected() -> None:
    assets = _scan_c("int f(void) {\n  return NID_ED25519;\n}\n")
    assert _by_rule(assets, "R-399")
    assert _by_rule(assets, "R-399")[0].purpose.value == "digital_signature"


def test_evp_pkey_rsa_is_ambiguous_not_keygen() -> None:
    assets = _scan_c(
        "int f(EVP_PKEY_CTX *ctx) {\n"
        "  EVP_PKEY_CTX_set_id(ctx, EVP_PKEY_RSA);\n"
        "  return 0;\n}\n"
    )
    assert _by_rule(assets, "R-350")
    rsa = _by_rule(assets, "R-350")[0]
    assert rsa.algorithm == "RSA"
    assert rsa.purpose.value == "unknown"
    assert rsa.evidence.ambiguity_status == "needs_enrichment"


def test_ambiguous_generic_evp_stays_unknown() -> None:
    assets = _scan_c(
        "int f(EVP_CIPHER_CTX *c) {\n"
        "  return EVP_CipherInit_ex(c, NULL, NULL, NULL, NULL, 0);\n"
        "}\n"
    )
    assert _by_rule(assets, "R-367")
    assert _by_rule(assets, "R-367")[0].purpose.value == "unknown"


def test_curve_nid_resolves_curve() -> None:
    assets = _scan_c(
        "int f(void) {\n"
        "  EC_KEY *k = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);\n"
        "  (void)k;\n  return 0;\n}\n"
    )
    assert _by_rule(assets, "R-341")
    asset = _by_rule(assets, "R-341")[0]
    assert asset.evidence.observed_symbol == "EC_KEY_new_by_curve_name"


def test_comment_and_string_c_symbols_not_matched() -> None:
    assets = _scan_c(
        "/* EVP_sha256 is great */\n"
        "const char *s = \"EVP_sha256\";\n"
        "int f(void) { return 0; }\n"
    )
    assert _by_rule(assets, "R-372") == []
    assert all(a.evidence.rule_id != "R-372" for a in assets)


def test_duplicate_cert_observations_normalize() -> None:
    from ecdat.engines.inventory import CryptoAssetInventory
    from ecdat.schemas import (
        AssetClassification,
        BusinessCriticality,
        CryptoAsset,
        CryptoPurpose,
        DetectionMethod,
        Evidence,
        FindingType,
        LifecycleStage,
        SensitivityLevel,
        SourceLocation,
    )

    def _cert_asset(algorithm: str, path: str) -> CryptoAsset:
        return CryptoAsset(
            algorithm=algorithm,
            purpose=CryptoPurpose.KEY_ESTABLISHMENT,
            location=f"{path}:0",
            source_surface="certificate",
            classification=AssetClassification.INFRASTRUCTURE,
            sensitivity=SensitivityLevel.CRITICAL,
            business_criticality=BusinessCriticality.CRITICAL,
            lifecycle_stage=LifecycleStage.ACTIVE,
            evidence=Evidence(
                detection_method=DetectionMethod.CERTIFICATE_PARSER,
                finding_type=FindingType.DETERMINISTIC,
                rule_id="C-001",
                location=SourceLocation(file_path=path),
                source_surface="certificate",
                confidence=0.99,
            ),
        )

    inventory = CryptoAssetInventory(scan_id="norm-test")
    for size, name in ((1024, "ee-cert-1024.pem"), (2048, "ee-cert-2048.pem"),
                       (3072, "ee-cert-3072.pem")):
        inventory.add_asset(_cert_asset(f"RSA-{size}", f"test/certs/{name}"))
    assert inventory.observation_count == 3
    groups = inventory.normalized_groups()
    rsa_groups = [g for g in groups if g.family == "RSA"]
    assert rsa_groups
    assert rsa_groups[0].observation_count == 3
    assert rsa_groups[0].variants == {
        "RSA-1024": 1, "RSA-2048": 1, "RSA-3072": 1}


def test_certificate_key_relationship() -> None:
    from ecdat.engines.relationships import build_relationships
    from ecdat.schemas import (
        AssetClassification,
        BusinessCriticality,
        CryptoAsset,
        CryptoPurpose,
        DetectionMethod,
        Evidence,
        FindingType,
        LifecycleStage,
        SensitivityLevel,
        SourceLocation,
    )

    def _asset(asset_id: str, algorithm: str, purpose: str,
               serial: str) -> CryptoAsset:
        return CryptoAsset(
            asset_id=asset_id,
            algorithm=algorithm,
            purpose=CryptoPurpose(purpose),
            location="test/cert.pem",
            source_surface="certificate",
            classification=AssetClassification.INFRASTRUCTURE,
            sensitivity=SensitivityLevel.CRITICAL,
            business_criticality=BusinessCriticality.CRITICAL,
            lifecycle_stage=LifecycleStage.ACTIVE,
            certificate_serial=serial,
            evidence=Evidence(
                detection_method=DetectionMethod.CERTIFICATE_PARSER,
                finding_type=FindingType.DETERMINISTIC,
                rule_id="C-001",
                location=SourceLocation(file_path="test/cert.pem"),
                source_surface="certificate",
                confidence=0.99,
            ),
        )

    assets = [
        _asset("key-1", "RSA-2048", "key_establishment", "0xabc"),
        _asset("hash-1", "SHA-256", "hashing", "0xabc"),
    ]
    rels = build_relationships(assets)
    kinds = {(r["from_id"], r["to_id"], r["kind"]) for r in rels}
    # Same unordered pair may carry both directed meanings (uses-key one
    # way, signed-with the other), but no exact triple repeats.
    assert len(rels) == len(kinds)
    assert ("hash-1", "key-1", "cert_uses_key") in kinds
    assert ("key-1", "hash-1", "cert_signed_with") in kinds


def test_source_invokes_requires_invocation_evidence() -> None:
    """source_invokes must not fan out through shared allocator names."""
    from ecdat.engines.relationships import build_relationships
    from ecdat.schemas import (
        AssetClassification,
        BusinessCriticality,
        CryptoAsset,
        CryptoPurpose,
        DetectionMethod,
        Evidence,
        FindingType,
        LifecycleStage,
        SensitivityLevel,
        SourceLocation,
    )

    def _src(asset_id: str, observed: str, siblings: list[str],
             snippet: str) -> CryptoAsset:
        return CryptoAsset(
            asset_id=asset_id,
            algorithm="AES-256-GCM",
            purpose=CryptoPurpose.ENCRYPTION,
            location=f"f.c:{asset_id}",
            source_surface="source_code",
            classification=AssetClassification.APPLICATION,
            sensitivity=SensitivityLevel.INTERNAL,
            business_criticality=BusinessCriticality.LOW,
            lifecycle_stage=LifecycleStage.ACTIVE,
            evidence=Evidence(
                detection_method=DetectionMethod.AST_RULE,
                finding_type=FindingType.DETERMINISTIC,
                rule_id="R-362",
                location=SourceLocation(
                    file_path="f.c", line_number=1, snippet=snippet),
                source_surface="source_code",
                confidence=0.9,
                observed_symbol=observed,
                sibling_symbols=siblings,
            ),
        )

    # Genuine pair: init statement actually invokes the fetched cipher.
    holder = _src("holder", "EVP_EncryptInit_ex", ["EVP_aes_256_gcm"],
                  "EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, k, iv)")
    target = _src("target", "EVP_aes_256_gcm", [],
                  "EVP_aes_256_gcm()")
    # Noise: shared allocator name, never invoked in the snippet.
    noisy = _src("noisy", "EVP_EncryptInit_ex", ["OPENSSL_zalloc"],
                 "EVP_EncryptInit_ex(ctx, c, NULL, NULL, NULL)")
    alloc = _src("alloc", "OPENSSL_zalloc", [], "OPENSSL_zalloc(sizeof(x))")
    rels = build_relationships([holder, target, noisy, alloc])
    invokes = {(r["from_id"], r["to_id"]) for r in rels
               if r["kind"] == "source_invokes"}
    assert ("holder", "target") in invokes
    assert ("noisy", "alloc") not in invokes


def test_unknown_purpose_gets_actionable_mapping() -> None:
    from ecdat.engines.recommendation_engine import RecommendationEngine

    assets = _scan_c(
        "int f(RSA *r) {\n  RSA *x = RSA_new();\n  (void)x; (void)r;\n  return 0;\n}\n")
    assert _by_rule(assets, "R-331")
    assert _by_rule(assets, "R-331")[0].purpose.value == "unknown"
    engine = RecommendationEngine()
    scored = engine.process(assets)
    rec = scored[0].recommendation
    assert rec is not None
    assert "UNKNOWN" not in rec.standardized_replacement
    assert "ML-KEM" in rec.standardized_replacement
    assert "ML-DSA" in rec.standardized_replacement


def test_rsa_keygen_maps_to_mlkem() -> None:
    from ecdat.engines.recommendation_engine import RecommendationEngine

    assets = _scan_c("int f(RSA *r) {\n  RSA_generate_key_ex(r, 2048, NULL, NULL);\n}\n")
    engine = RecommendationEngine()
    scored = engine.process(assets)
    rec = scored[0].recommendation
    assert rec is not None
    assert "ML-KEM" in rec.standardized_replacement


def test_ecdsa_sign_maps_to_mldsa() -> None:
    from ecdat.engines.recommendation_engine import RecommendationEngine

    assets = _scan_c("int f(void) {\n  ECDSA_sign(0, NULL, 0, NULL, NULL, NULL);\n}\n")
    engine = RecommendationEngine()
    scored = engine.process(assets)
    rec = scored[0].recommendation
    assert rec is not None
    assert "ML-DSA" in rec.standardized_replacement


def test_dsa_sign_never_maps_to_mlkem() -> None:
    from ecdat.engines.recommendation_engine import RecommendationEngine

    assets = _scan_c("int f(void) {\n  DSA_sign(0, NULL, 0, NULL, NULL, NULL);\n}\n")
    assert _by_rule(assets, "R-392")
    engine = RecommendationEngine()
    scored = engine.process(assets)
    rec = scored[0].recommendation
    assert rec is not None
    assert "ML-KEM" not in rec.standardized_replacement
    assert "ML-DSA" in rec.standardized_replacement or "SLH-DSA" in rec.standardized_replacement


def test_liboqs_corpus_still_detected() -> None:
    assets = _scan_c(
        "int f(void) {\n"
        "  OQS_KEM *k = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);\n"
        "  OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);\n"
        "  OQS_KEM_ml_kem_768_keypair(NULL, NULL);\n"
        "  OQS_SIG_ml_dsa_65_sign(NULL, NULL, NULL, 0, NULL);\n"
        "  return k != NULL;\n}\n"
    )
    assert _by_rule(assets, "R-310")
    assert _by_rule(assets, "R-314")
    assert _by_rule(assets, "R-318")
    assert _by_rule(assets, "R-319")
