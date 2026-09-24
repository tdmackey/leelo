use crate::observation::Operation;
use crate::{Command, Result, enrollment, providers::Providers, read_array};
use leelo_engine::observation::OperationReport;

pub(super) fn run(command: Command) -> Result<()> {
    let name = match &command {
        Command::Enroll { .. } => "enroll",
        Command::ResumeEnrollment { .. } => "resume",
        Command::Unlock {
            mapping: Some(_), ..
        } => "activate",
        Command::Unlock { .. } => "check",
        Command::PcrDigest { tcti, pcr_mask } => {
            let mut tpm = leelo_tpm::Tpm2Provider::new(tcti)?;
            println!("{}", hex::encode(tpm.pcr_digest(*pcr_mask)?));
            return Ok(());
        }
        _ => return Err("unexpected platform command".into()),
    };
    let mut observed = Operation::new(name, leelo_telemetry::Emitter::from_env());
    let result = run_observed(command, &mut observed);
    observed.finish(&result);
    result
}
fn run_observed(command: Command, observed: &mut Operation) -> Result<()> {
    match command {
        command @ (Command::Enroll { .. } | Command::ResumeEnrollment { .. }) => {
            enrollment::run(command, observed)
        }
        Command::Unlock {
            device,
            config,
            trust_key,
            token,
            tcti,
            mapping,
            check_only: _,
        } => {
            let mut providers = Providers::read(&config)?;
            observed.configure_providers(providers.provider_ids());
            let trusted = read_array(&trust_key)?;
            let mut luks = leelo_luks::Luks2::open(&device, false)?;
            let token = luks.token(token)?;
            let mut tpm = leelo_tpm::Tpm2Provider::new(&tcti)?;
            observed.stage("recover");
            let mut report = OperationReport::default();
            let recovered = leelo_engine::unlock_observed(
                &token.bytes,
                &trusted,
                &luks.uuid(),
                token.slot,
                &mut providers.network,
                &mut tpm,
                &mut report,
            );
            observed.engine(&report);
            let recovered = recovered?;
            if let Some(name) = mapping {
                observed.stage("activate");
                luks.activate(token.slot, recovered.credential.as_ref(), &name)?;
                println!("activated {name}");
            } else {
                observed.stage("check");
                luks.test_credential(Some(token.slot), recovered.credential.as_ref())?;
                println!("unlock verified; no mapping created");
            }
            Ok(())
        }
        _ => Err("unexpected platform command".into()),
    }
}
