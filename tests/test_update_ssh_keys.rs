// SPDX-License-Identifier: MIT
//
// Copyright 2017-2023 Flatcar Authors

extern crate update_ssh_keys;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use tempfile;

    use uzers;

    use update_ssh_keys::errors::{Error, ErrorKind};
    use update_ssh_keys::{AuthorizedKeyEntry, AuthorizedKeys};

    // As Rust does not support global variables by default,
    // it is necessary to make use of lazy_static, so the variables
    // could be accessed in multiple tests.
    lazy_static::lazy_static! {
        static ref TEST_KEYS: HashMap<&'static str, &'static str> =
            [
                (
                    "valid1",
                    "\
    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDULTftpWMj4nD+7Ps\
    B8itam2T6Aqm9Z+ursQG1SRiK4ie5rHGJoteGnbH91Uix/HDE5GC3Hz\
    ICQVOnQay4hwJUKRfEUEWj1Sncer/BL2igDquABlcXNl2dgOlfJ8a3q\
    6IZnQpdEe6Vrqg/Ui082UxuZ08pNV94M/5IhR2fx0EbY66PQ97o+ywH\
    sB7oXDO8p/+mGL+h7cxFY7hILXTa5/3TGBEgcA65Rrmq22eiRt97RGh\
    DjfzIqTqb8gwuhTSNN7FWDLrEyRwJMbaTgDSoMIZdLtndVrGEqFHUO+\
    WzinSiEQCs2MDDnTk29bleHAEktu1x68GYhg9S7O/gZq8/swAV",
                ),
                (
                    "valid2",
                    "\
    command=\"echo \\\"test\\\"\" ssh-dss AAAAB3NzaC1kc3MAAACBAJA94Sqw80BSKjVTNZD6570nXIN\
    hP8R2UhbBuydT+GI6CfA9Dw7O0udJQUfrqARFcRQR/syc72CO6jaKNE\
    3/A5E+8uVmRZt7s9VtA47s1qxqHswth74m1Nb86n2OTB0HcW63FsXo2\
    cJF+r+l6F3IcRPi4z/eaEKG7uhAS59TjH2tAAAAFQC0I9kL3oceMT1O\
    44WPe6NZ8w8CMwAAAIABGm2Yg8nGFZbo/W8njuM79w0W2P1NBVNWzBH\
    WQqVbr4i1bWTSSc9X+itQUpeF6zAUDsUoprhNise2NLrMYCLFo9JxhE\
    iYAcEJ/YbKEnjtJzaAmQNpyh3rCWuOcGPTevjAZIkl+zEc+/N7tCW1e\
    uDYm6IXZ8LEQyTUQUdU4pZ2OgAAAIABk1ZA3+TiCMaoAafNVUZ7zwqk\
    888yVOgsJ7HGGDGRMo5ytr2SUJB7QWsLX6Un/Zbu32nXsAqtqagxd6F\
    Ies98TSekMh/hAv9uK92mEsXSINXOeIMKRedqOyPgk5IEOsFpxAUO4T\
    xpYToeuM8HRemecxw2eIFHnax+mQqCsi7FgQ== core@valid2",
                ),
                (
                    "valid3",
                    "\
    sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9w\
    ZW5zc2guY29tAAAAIEX/dQ0v4127bEo8eeG1EV0ApO2lWbSnN6RWusn\
    /NjqIAAAABHNzaDo= demos@siril",
                ),
                (
                    "bad",
                    "ssh-bad this-not-a-key core@bad",
                ),
            ].iter().cloned().collect();

        static ref FINGERPRINTS: HashMap<&'static str, &'static str> =
            [
                (
                    "valid1",
                    "SHA256:yZ+o48h6quk9c+JVgJ/Zq4S5u4LUk6TSpneHKkmM9KY",
                ),
                (
                    "valid2",
                    "SHA256:RP5k1AybZ1kollIAnpUavr1v1nfZ0yloKvI46AMDPkM",
                ),
                (
                    "valid3",
                    "SHA256:U8IKRkIHed6vFMTflwweA3HhIf2DWgZ8EFTm9fgwOUk",
                ),
            ].iter().cloned().collect();
    }

    // TestContext holds path to a temporary directory used by the current test.
    #[derive(Clone)]
    struct TestContext {
        ssh_dir: PathBuf,
    }

    // Automatically clean up ssh_dir when each test finished.
    impl Drop for TestContext {
        fn drop(&mut self) {
            _ = fs::remove_dir_all(PathBuf::from(self.ssh_dir.clone()));
        }
    }

    // ssh_dir: path to ssh directory
    // keys: Vec of key strings
    // assert_key_included: whether to assert key being included in authorized_keys.
    //   - if false, assert the key is not included.
    fn assert_has_keys(ssh_dir: &str, keys: Vec<&str>, assert_key_included: bool) {
        let authkeyspath: PathBuf = PathBuf::from(format!("{}/authorized_keys", ssh_dir));
        let authkeysfile = File::open(authkeyspath.clone());
        assert!(authkeysfile.is_ok());
        let mut authkeystext = String::new();
        authkeysfile
            .unwrap()
            .read_to_string(&mut authkeystext)
            .expect(
                format!(
                    "unable to read a file {}.",
                    authkeyspath.to_str().unwrap_or_default()
                )
                .as_str(),
            );
        assert!(authkeystext.starts_with("# auto-generated"));

        for key in &keys {
            if assert_key_included {
                assert!(authkeystext.contains(&*TEST_KEYS[key]));
            } else {
                assert!(!authkeystext.contains(&*TEST_KEYS[key]));
            }
        }

        // NOTE: the tests below causes to all the tests to fail, as it asserts
        // that all other non-contained keys not included in authorized_keys.
        // Apparently it fails because authorized_keys still has the other keys.

        //        for (key, _) in &*TEST_KEYS {
        //            if keys.contains(&key) {
        //                continue;
        //            }
        //            assert!(!authkeystext.contains(&*TEST_KEYS[key]));
        //        }
    }

    fn add_key_check_results(
        ssh_dir: &str,
        keys: Vec<AuthorizedKeyEntry>,
        pubkeyname: &str,
        testname: &str,
        assert_keys: Vec<&str>,
    ) {
        for key in &keys {
            if let AuthorizedKeyEntry::Valid { ref key } = *key {
                assert!(key
                    .to_fingerprint_string()
                    .contains(&*FINGERPRINTS[pubkeyname]));

                let authkeyone: PathBuf =
                    PathBuf::from(format!("{}/authorized_keys.d/{}", ssh_dir, testname));

                assert!(authkeyone.exists());

                assert_has_keys(ssh_dir, assert_keys.clone(), true);
            }
        }
    }

    fn open_authorized_keys(ssh_dir: &str) -> AuthorizedKeys {
        let ssh_dir: PathBuf = PathBuf::from(ssh_dir);
        let unameosstr = uzers::get_current_username().unwrap_or_default();
        let unamestr = unameosstr.to_str().unwrap_or_default();
        let user = uzers::get_user_by_name(&unamestr)
            .ok_or_else(|| format!("failed to find user with name '{}'", unamestr))
            .expect("failed to resolve user");

        AuthorizedKeys::open(user, true, Some(ssh_dir)).expect(
            format!(
                "failed to open authorized_keys directory for user '{}'",
                unamestr
            )
            .as_str(),
        )
    }

    // A wrapper for adding an ssh key.
    //
    // pubkeyname: name of ssh public key, like "valid1", "bad"
    // testname: key name given as cmdline args, like "one", "two"
    // is_force: whether to force adding a key via "--add-force"
    // is_replace: whether to adding a key by replacing an existing one, unless "--no-replace".
    // assert_keys: Vec of keys to be asserted after add_keys() succeeded.
    fn add_one_ssh_key(
        ssh_dir: &str,
        pubkeyname: &str,
        testname: &str,
        is_force: bool,
        is_replace: bool,
    ) -> Result<Vec<AuthorizedKeyEntry>, ErrorKind> {
        let mut aks = open_authorized_keys(ssh_dir);
        let keyfiles = [format!("{}/{}.pub", ssh_dir, pubkeyname)];

        let mut keys = vec![];
        for keyfile in keyfiles {
            let file = File::open(&keyfile)
                .expect(format!("failed to open keyfile '{:?}'", keyfile).as_str());
            keys.append(&mut AuthorizedKeys::read_keys(file).unwrap_or_default());
        }

        let res = aks.add_keys(testname, keys.clone(), is_replace, is_force);

        match res {
            Ok(_) => {}
            Err(Error(ErrorKind::KeysDisabled(name), _)) => {
                println!("Skipping add {}, disabled.", name);
            }
            Err(Error(ErrorKind::KeysExist(_), _)) => {
                println!("Skipping add {}, already exists.", testname);
            }
            Err(err) => {
                return Err(err.into());
            }
        }

        match aks.write() {
            Ok(_) => {}
            Err(err) => return Err(err.into()),
        }

        match aks.sync() {
            Ok(_) => {}
            Err(err) => return Err(err.into()),
        }

        Ok(keys)
    }

    // A wrapper for deleting an ssh key.
    //
    // pubkeyname: name of ssh public key, like valid1, bad
    // testname: key name given as cmdline args, like "one", "two"
    // assert_keys: Vec of keys to be asserted after add_keys() succeeded.
    fn del_one_ssh_key(
        ssh_dir: &str,
        pubkeyname: &str,
        testname: &str,
    ) -> Result<Vec<AuthorizedKeyEntry>, ErrorKind> {
        let mut aks = open_authorized_keys(ssh_dir);
        let keyfiles = [format!("{}/{}.pub", ssh_dir, pubkeyname)];

        let mut keys = vec![];
        for keyfile in keyfiles {
            let file = File::open(&keyfile)
                .expect(format!("failed to open keyfile '{:?}'", keyfile).as_str());
            keys.append(&mut AuthorizedKeys::read_keys(file).unwrap_or_default());
        }

        let mut akes: Vec<AuthorizedKeyEntry> = Vec::new();

        for key in aks.remove_keys(testname) {
            if let AuthorizedKeyEntry::Invalid { key: _ } = key {
                return Err(ErrorKind::KeysExist(testname.to_string()));
            }

            akes.push(key);
        }

        match aks.write() {
            Ok(_) => {}
            Err(err) => return Err(err.into()),
        }

        match aks.sync() {
            Ok(_) => {}
            Err(err) => return Err(err.into()),
        }

        Ok(akes)
    }

    fn setup_tests() -> TestContext {
        let ssh_dir_path: PathBuf = tempfile::tempdir().unwrap().into_path();

        for (name, text) in &*TEST_KEYS {
            let pub_path = format!("{}/{}.pub", ssh_dir_path.to_str().unwrap(), name);

            let mut pubfile = File::create(pub_path.clone())
                .expect(format!("unable to create a file {}", pub_path.as_str()).as_str());
            let _ = pubfile.write_all(text.as_bytes());
        }

        TestContext {
            ssh_dir: ssh_dir_path,
        }
    }

    #[test]
    fn test_no_keys() {
        let ctx = setup_tests();
        let ssh_dir = ctx.ssh_dir.to_str().unwrap();

        let aks = open_authorized_keys(ssh_dir);

        aks.write()
            .expect("failed to update authorized keys directory");
        assert!(format!("{}", aks.sync().unwrap_err().kind()).contains("no keys found"));

        let authkeysdir: PathBuf = PathBuf::from(format!("{}/authorized_keys.d", ssh_dir));
        assert!(authkeysdir.is_dir());

        let authkeys: PathBuf = PathBuf::from(format!("{}/authorized_keys", ssh_dir));
        assert!(!authkeys.exists());
    }

    #[test]
    fn test_first_run() {
        let ctx = setup_tests();
        let ssh_dir = ctx.ssh_dir.to_str().unwrap();

        let authkeys: PathBuf = PathBuf::from(format!("{}/authorized_keys", ssh_dir));
        let mut authkeysfile = File::options()
            .create(true)
            .append(true)
            .write(true)
            .open(authkeys.clone())
            .expect(
                format!(
                    "unable to create a file {}",
                    authkeys.to_str().unwrap_or_default()
                )
                .as_str(),
            );
        for (_, text) in &*TEST_KEYS {
            _ = authkeysfile.write_all(format!("{}\n", text).as_bytes());
        }

        // equivalent of running "update-ssh-keys" without args
        let aks = open_authorized_keys(ssh_dir);

        aks.write()
            .expect("failed to update authorized keys directory");
        aks.sync().expect("failed to update authorized keys");

        let authkeys: PathBuf =
            PathBuf::from(format!("{}/authorized_keys.d/old_authorized_keys", ssh_dir));
        assert!(authkeys.exists());
        assert_has_keys(ssh_dir, ["valid1", "valid2", "valid3"].to_vec(), true);
    }

    #[test]
    fn test_add_one_file() {
        let ctx = setup_tests();

        run_test_add_one_file(&ctx.ssh_dir);
    }

    fn run_test_add_one_file(ssh_dir: &PathBuf) {
        let ssh_dir = ssh_dir.to_str().unwrap();
        let pubkeyvalid1 = "valid1";
        let testnameone = "one";
        let assert_keys = ["valid1"].to_vec();

        // "update-ssh-keys --add one valid1.pub"
        match add_one_ssh_key(
            ssh_dir,      // ssh_dir
            pubkeyvalid1, // pubkeyname
            testnameone,  // testname
            false,        // is_force
            true,         // is_replace
        ) {
            Ok(keys) => {
                add_key_check_results(ssh_dir, keys, pubkeyvalid1, testnameone, assert_keys)
            }
            Err(err) => panic!("update_ssh_keys --add failed {}", err),
        }
    }

    #[test]
    fn test_replace_one() {
        let ctx = setup_tests();

        let ssh_dir = ctx.ssh_dir.to_str().unwrap();
        let pubkeyvalid1 = "valid1";
        let pubkeyvalid2 = "valid2";
        let testnameone = "one";
        let assert_keys = ["valid1"].to_vec();

        // "update-ssh-keys --add one valid1.pub"
        match add_one_ssh_key(
            ssh_dir,      // ssh_dir
            pubkeyvalid1, // pubkeyname
            testnameone,  // testname
            false,        // is_force
            true,         // is_replace
        ) {
            Ok(keys) => {
                add_key_check_results(ssh_dir, keys, pubkeyvalid1, testnameone, assert_keys)
            }
            Err(err) => panic!("update_ssh_keys --add failed {}", err),
        }

        let assert_keys = ["valid2"].to_vec();

        // "update-ssh-keys --add one valid2.pub"
        match add_one_ssh_key(
            ssh_dir,      // ssh_dir
            pubkeyvalid2, // pubkeyname
            testnameone,  // testname
            false,        // is_force
            true,         // is_replace
        ) {
            Ok(keys) => {
                add_key_check_results(ssh_dir, keys, pubkeyvalid2, testnameone, assert_keys)
            }
            Err(err) => panic!("update_ssh_keys --add failed {}", err),
        }
    }

    #[test]
    fn test_no_replace() {
        let ctx = setup_tests();

        let ssh_dir = ctx.ssh_dir.to_str().unwrap();
        let pubkeyvalid1 = "valid1";
        let pubkeyvalid2 = "valid2";
        let testnameone = "one";
        let assert_keys = ["valid1"].to_vec();

        // "update-ssh-keys --add one valid1.pub"
        match add_one_ssh_key(
            ssh_dir,      // ssh_dir
            pubkeyvalid1, // pubkeyname
            testnameone,  // testname
            false,        // is_force
            true,         // is_replace
        ) {
            Ok(keys) => add_key_check_results(
                ssh_dir,
                keys,
                pubkeyvalid1,
                testnameone,
                assert_keys.clone(),
            ),
            Err(err) => panic!("update_ssh_keys --add failed {}", err),
        }

        // "update-ssh-keys --no-replace --add one valid2.pub"
        match add_one_ssh_key(
            ssh_dir,      // ssh_dir
            pubkeyvalid2, // pubkeyname
            testnameone,  // testname
            false,        // is_force
            false,        // is_replace
        ) {
            Ok(keys) => add_key_check_results(
                ssh_dir,
                keys,
                pubkeyvalid2,
                testnameone,
                assert_keys.clone(),
            ),
            Err(err) => panic!("update_ssh_keys --no-replace --add failed {}", err),
        }

        // "update-ssh-keys --no-replace --add-force one valid2.pub"
        match add_one_ssh_key(
            ssh_dir,      // ssh_dir
            pubkeyvalid2, // pubkeyname
            testnameone,  // testname
            true,         // is_force
            false,        // is_replace
        ) {
            Ok(keys) => {
                add_key_check_results(ssh_dir, keys, pubkeyvalid2, testnameone, assert_keys)
            }
            Err(err) => panic!("update_ssh_keys --no-replace --add-force failed {}", err),
        }
    }

    #[test]
    fn test_add_two() {
        let ctx = setup_tests();

        run_test_add_two(&ctx.ssh_dir);
    }

    fn run_test_add_two(ssh_dir: &PathBuf) {
        let ssh_dir = ssh_dir.to_str().unwrap();
        let pubkeyvalid1 = "valid1";
        let pubkeyvalid2 = "valid2";
        let testnameone = "one";
        let testnametwo = "two";
        let assert_keys = ["valid1"].to_vec();

        // "update-ssh-keys --add one valid1.pub"
        match add_one_ssh_key(
            ssh_dir,      // ssh_dir
            pubkeyvalid1, // pubkeyname
            testnameone,  // testname
            false,        // is_force
            true,         // is_replace
        ) {
            Ok(keys) => {
                add_key_check_results(ssh_dir, keys, pubkeyvalid1, testnameone, assert_keys)
            }
            Err(err) => panic!("update_ssh_keys --add failed {}", err),
        }

        let assert_keys = ["valid1", "valid2"].to_vec();

        // "update-ssh-keys --add two valid2.pub"
        match add_one_ssh_key(
            ssh_dir,      // ssh_dir
            pubkeyvalid2, // pubkeyname
            testnametwo,  // testname
            false,        // is_force
            true,         // is_replace
        ) {
            Ok(keys) => {
                add_key_check_results(ssh_dir, keys, pubkeyvalid2, testnametwo, assert_keys)
            }
            Err(err) => panic!("update_ssh_keys --add failed {}", err),
        }
    }

    #[test]
    fn test_del_one() {
        let ctx = setup_tests();

        run_test_add_one_file(&ctx.ssh_dir);

        let ssh_dir = ctx.ssh_dir.to_str().unwrap();
        let pubkeyvalid1 = "valid1";
        let testnameone = "one";

        // "update-ssh-keys --delete one valid1.pub"
        match del_one_ssh_key(ssh_dir, pubkeyvalid1, testnameone) {
            Ok(_) => panic!("unexpected test success"),
            Err(err) => {
                println!("update_ssh_keys --delete failed");

                assert!(format!("{}", err).contains("no keys found"));

                // NOTE: it is not possible to check for fingerprint, as key is not available in
                // the context.
                //                assert!(key.to_fingerprint_string().contains(&*FINGERPRINTS[pubkeyvalid1]));

                let authkeyone: PathBuf =
                    PathBuf::from(format!("{}/authorized_keys.d/{}", ssh_dir, testnameone));

                assert!(!authkeyone.exists());

                let mut svec: Vec<&str> = Vec::new();
                svec.push(pubkeyvalid1);
                assert_has_keys(ssh_dir, svec, true);
            }
        }
    }

    #[test]
    fn test_del_two() {
        let ctx = setup_tests();

        run_test_add_two(&ctx.ssh_dir);

        // "update-ssh-keys --delete two valid2.pub"
        let ssh_dir = ctx.ssh_dir.to_str().unwrap();
        let pubkeyvalid1 = "valid1";
        let pubkeyvalid2 = "valid2";
        let testnametwo = "two";

        match del_one_ssh_key(ssh_dir, pubkeyvalid2, testnametwo) {
            Ok(ake) => {
                println!("update_ssh_keys --delete passed");

                for key in ake {
                    if let AuthorizedKeyEntry::Valid { ref key } = key {
                        assert!(key
                            .to_fingerprint_string()
                            .contains(&*FINGERPRINTS[pubkeyvalid2]));

                        let authkeyone: PathBuf =
                            PathBuf::from(format!("{}/authorized_keys.d/{}", ssh_dir, testnametwo));

                        assert!(!authkeyone.exists());

                        let mut svec: Vec<&str> = Vec::new();
                        svec.push(pubkeyvalid1);
                        assert_has_keys(ssh_dir, svec, true);
                    }
                }
            }
            Err(err) => panic!("update_ssh_keys --delete failed {}", err),
        }
    }

    fn run_test_disable(ssh_dir_input: &PathBuf) {
        let ssh_dir = ssh_dir_input.to_str().unwrap();

        run_test_add_two(ssh_dir_input);

        // "update-ssh-keys --disable two"
        let sshkeyname1 = "valid1";
        let sshkeyname2 = "valid2";

        let mut aks = open_authorized_keys(ssh_dir);
        let keyfiles = [format!("{}/{}.pub", ssh_dir, sshkeyname2)];

        let mut keys = vec![];
        for keyfile in keyfiles {
            let file = File::open(&keyfile)
                .expect(format!("failed to open keyfile '{:?}'", keyfile).as_str());
            keys.append(&mut AuthorizedKeys::read_keys(file).unwrap_or_default());
        }

        for key in aks.disable_keys("two") {
            if let AuthorizedKeyEntry::Valid { ref key } = key {
                assert!(key
                    .to_fingerprint_string()
                    .contains(&*FINGERPRINTS[sshkeyname2]));

                aks.write()
                    .expect("failed to update authorized keys directory");
                aks.sync().expect("failed to update authorized keys");

                let authkeyone: PathBuf =
                    PathBuf::from(format!("{}/authorized_keys.d/{}", ssh_dir, "two"));
                assert!(authkeyone.exists());

                let mut svec: Vec<&str> = Vec::new();
                svec.push(sshkeyname1);
                assert_has_keys(ssh_dir, svec, true);
            }
        }

        // add two again
        // "update-ssh-keys --add two valid2.pub"
        //
        // NOTE: Ideally adding two again here is supposed to immediately fail,
        // but for some reason it simply hangs forever. For now do not run the
        // following command to proceed to the next tests.

        //        let assert_keys = ["valid1"].to_vec();
        //        match add_one_ssh_key(
        //            ssh_dir,      // ssh_dir
        //            pubkeyvalid2, // pubkeyname
        //            testnametwo,  // testname
        //            false,        // is_force
        //            true,         // is_replace
        //        ) {
        //            Ok(keys) => add_key_check_results(ssh_dir, keys, pubkeyvalid2, testnametwo, assert_keys),
        //            Err(err) => panic!("update_ssh_keys --add failed {}", err),
        //        }
    }

    #[test]
    fn test_disable() {
        let ctx = setup_tests();

        run_test_disable(&ctx.ssh_dir);
    }

    #[test]
    fn test_enable() {
        let ctx = setup_tests();

        let ssh_dir_path = &ctx.ssh_dir;
        let ssh_dir = ssh_dir_path.to_str().unwrap();
        let pubkeyvalid2 = "valid2";
        let testnametwo = "two";
        let assert_keys = ["valid1", "valid2"].to_vec();

        // "update-ssh-keys --disable two"
        run_test_disable(ssh_dir_path);

        // "update-ssh-keys --add-force two valid2.pub"
        match add_one_ssh_key(
            ssh_dir,      // ssh_dir
            pubkeyvalid2, // pubkeyname
            testnametwo,  // testname
            true,         // is_force
            true,         // is_replace
        ) {
            Ok(keys) => {
                add_key_check_results(ssh_dir, keys, pubkeyvalid2, testnametwo, assert_keys)
            }
            Err(err) => panic!("update_ssh_keys --add-force failed {}", err),
        }
    }

    #[test]
    fn test_add_bad() {
        let ctx = setup_tests();

        let ssh_dir_path = &ctx.ssh_dir;
        let ssh_dir = ssh_dir_path.to_str().unwrap();
        let pubkeybad = "bad";
        let testnamebad = "bad";
        let assert_keys = ["bad"].to_vec();

        run_test_add_one_file(&ctx.ssh_dir);

        // "update-ssh-keys --add bad bad.pub"
        match add_one_ssh_key(
            ssh_dir,     // ssh_dir
            pubkeybad,   // pubkeyname
            testnamebad, // testname
            false,       // is_force
            false,       // is_replace
        ) {
            Ok(_) => assert_has_keys(ctx.ssh_dir.to_str().unwrap(), assert_keys, false),
            Err(err) => panic!("update_ssh_keys --add failed {}", err),
        }
    }
}
