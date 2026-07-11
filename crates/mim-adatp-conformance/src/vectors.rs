/// ADatP-4774 Table 17 test vector from surevine/spiffing reference suite.
pub struct AdatpVector {
    pub id: &'static str,
    pub description: &'static str,
    pub xml: &'static str,
    pub expect_valid: bool,
}

/// Official ADatP-4774 Annex B / Table 17 STANAG 4774 XML vectors.
pub const ADATP_VECTORS: &[AdatpVector] = &[
    AdatpVector {
        id: "nato-4774-17-1",
        description: "NATO UNCLASSIFIED Releasable to ISAF, KFOR, RESOLUTE SUPPORT",
        xml: include_str!("../fixtures/adatp/nato-4774-17-1.nato"),
        expect_valid: true,
    },
    AdatpVector {
        id: "nato-4774-17-2",
        description: "NATO UNCLASSIFIED",
        xml: include_str!("../fixtures/adatp/nato-4774-17-2.nato"),
        expect_valid: true,
    },
    AdatpVector {
        id: "nato-4774-17-3",
        description: "NATO UNCLASSIFIED - STAFF",
        xml: include_str!("../fixtures/adatp/nato-4774-17-3.nato"),
        expect_valid: true,
    },
    AdatpVector {
        id: "nato-4774-17-4",
        description: "NATO RESTRICTED Releasable to Japan, Switzerland, Ukraine",
        xml: include_str!("../fixtures/adatp/nato-4774-17-4.nato"),
        expect_valid: true,
    },
    AdatpVector {
        id: "nato-4774-17-5",
        description: "NATO/EAPC CONFIDENTIAL Releasable to ISAF",
        xml: include_str!("../fixtures/adatp/nato-4774-17-5.nato"),
        expect_valid: true,
    },
    AdatpVector {
        id: "nato-4774-17-6",
        description: "NATO/KFOR CONFIDENTIAL Ireland, Sweden, Ukraine, NATO ONLY",
        xml: include_str!("../fixtures/adatp/nato-4774-17-6.nato"),
        expect_valid: true,
    },
    AdatpVector {
        id: "nato-4774-extra-1",
        description: "COSMIC TOP SECRET",
        xml: include_str!("../fixtures/adatp/nato-4774-extra-1.nato"),
        expect_valid: true,
    },
];
