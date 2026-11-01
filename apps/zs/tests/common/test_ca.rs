//! A test control plane CA. It builds its certificates with the parameters the control plane
//! uses: a self-signed CA with only a common name and unconstrained basic constraints, and
//! client certificates signed from a device CSR whose subject is replaced by the device ID
//! (CN) and the organization (O), marked not a CA. Validity and key usage are rcgen's defaults,
//! as in the control plane.

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams,
    DistinguishedName, DnType, IsCa, KeyPair,
};

pub struct TestCa {
    cert: Certificate,
    key: KeyPair,
}

impl TestCa {
    pub fn generate(common_name: &str) -> Result<Self, String> {
        let key = KeyPair::generate().map_err(|e| e.to_string())?;
        let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, common_name.to_string());
        let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
        Ok(Self { cert, key })
    }

    pub fn certificate_pem(&self) -> String {
        self.cert.pem()
    }

    /// The CN comes from `device_id`, never the CSR, as in the control plane.
    pub fn issue_client_certificate(
        &self,
        csr_pem: &str,
        device_id: &str,
        organization: &str,
    ) -> Result<String, String> {
        let mut csr =
            CertificateSigningRequestParams::from_pem(csr_pem).map_err(|e| e.to_string())?;
        csr.params.is_ca = IsCa::ExplicitNoCa;
        csr.params.distinguished_name = DistinguishedName::new();
        csr.params
            .distinguished_name
            .push(DnType::CommonName, device_id.to_string());
        csr.params
            .distinguished_name
            .push(DnType::OrganizationName, organization.to_string());
        let issued = csr
            .signed_by(&self.cert, &self.key)
            .map_err(|e| e.to_string())?;
        Ok(issued.pem())
    }
}
