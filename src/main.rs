use hactool::extkeys::{extkeys_initialize_settings, extkeys_parse_titlekeys, parse_hex_key};
use hactool::hfs0::{hfs0_process, Hfs0Ctx};
use hactool::kip::{ini1_process, kip1_process, Ini1Ctx, Kip1Ctx};
use hactool::nax0::{nax0_process, Nax0Ctx};
use hactool::nca::{
    nca_process, NcaCtx, NcaSectionType, NCACONTENTTYPE_CONTROL, NCACONTENTTYPE_DATA,
    NCACONTENTTYPE_MANUAL, NCACONTENTTYPE_META, NCACONTENTTYPE_PROGRAM, NCACONTENTTYPE_PUBLICDATA,
};
use hactool::nca0_romfs::{nca0_romfs_process, Nca0RomfsCtx};
use hactool::npdm::{npdm_process, NpdmHeader, NPDM_HEADER_SIZE};
use hactool::nso::{nso0_process, Nso0Ctx};
use hactool::packages::{pk11_process, pk21_process, Pk11Ctx, Pk21Ctx};
use hactool::pfs0::{pfs0_process, Pfs0Ctx};
use hactool::pki::{pki_derive_keys, pki_initialize_keyset, pki_print_keys};
use hactool::romfs::{romfs_process, RomfsCtx};
use hactool::save::{save_process, SaveCtx};
use hactool::settings::HactoolCtx;
use hactool::types::{
    BaseFileType, FileType, Filepath, KeysetVariant, SharedFile, Validity, ACTION_DEV,
    ACTION_EXTRACT, ACTION_EXTRACTINI1, ACTION_INFO, ACTION_LISTFILES, ACTION_LISTROMFS,
    ACTION_ONLYUPDATEDROMFS, ACTION_RAW, ACTION_SAVEINIJSON, ACTION_VERIFY, MAGIC_META,
};
use hactool::utils::open_key_file;
use hactool::xci::{xci_process, XciCtx};
use std::env;
use std::fs::File;
use std::process;

fn usage(prog_name: &str) -> ! {
    eprint!(
        "hactool (c) SciresM.\n\
Built: 00:00:00 Nov 11 2026\n\
\n\
Usage: {} [options...] <file>\n\
Options:\n\
  -i, --info         Show file info.\n\
                         This is the default action.\n\
  -x, --extract      Extract data from file.\n\
                         This is also the default action.\n\
  -r, --raw          Keep raw data, don't unpack.\n\
  -y, --verify       Verify hashes and signatures.\n\
  -d, --dev          Decrypt with development keys instead of retail.\n\
  -q, --quiet        Suppress 'Saving ...' extraction output.\n\
  -k, --keyset       Load keys from an external file.\n\
  -t, --intype=type  Specify input file type [nca, xci, pfs0, romfs, hfs0, npdm, pk11, pk21, ini1, kip1, nax0, save, keygen]\n\
  --titlekey=key     Set title key for Rights ID crypto titles.\n\
  --contentkey=key   Set raw key for NCA body decryption.\n\
  --disablekeywarns  Disables warning output when loading external keys.\n\
NCA options:\n\
  --plaintext=file   Specify file path for saving a decrypted copy of the NCA.\n\
  --header=file      Specify Header file path.\n\
  --section0=file    Specify Section 0 file path.\n\
  --section1=file    Specify Section 1 file path.\n\
  --section2=file    Specify Section 2 file path.\n\
  --section3=file    Specify Section 3 file path.\n\
  --section0dir=dir  Specify Section 0 directory path.\n\
  --section1dir=dir  Specify Section 1 directory path.\n\
  --section2dir=dir  Specify Section 2 directory path.\n\
  --section3dir=dir  Specify Section 3 directory path.\n\
  --exefs=file       Specify ExeFS file path. Overrides appropriate section file path.\n\
  --exefsdir=dir     Specify ExeFS directory path. Overrides appropriate section directory path.\n\
  --romfs=file       Specify RomFS file path. Overrides appropriate section file path.\n\
  --romfsdir=dir     Specify RomFS directory path. Overrides appropriate section directory path.\n\
  --listromfs        List files in RomFS.\n\
  --baseromfs        Set Base RomFS to use with update partitions.\n\
  --basenca          Set Base NCA to use with update partitions.\n\
  --basefake         Use a fake Base RomFS with update partitions (all reads will return 0xCC).\n\
  --onlyupdated      Ignore non-updated files in update partitions.\n\
  --xcontenttype=    Only extract contents if the content type matches an expected one.\n\
                         Supported types are integers 0-9 or [program, meta, control, manual, data, publicdata].\n\
  --appendsectypes   Append a section type string to section paths.\n\
  --suppresskeys     Suppress output of decrypted keys.\n\
NPDM options:\n\
  --json=file        Specify file path for saving JSON representation of program permissions to.\n\
KIP1 options:\n\
  --json=file        Specify file path for saving JSON representation of program permissions to.\n\
  --uncompressed=f   Specify file path for saving uncompressed KIP1.\n\
NSO0 options:\n\
  --uncompressed=f   Specify file path for saving uncompressed NSO0.\n\
PFS0 options:\n\
  --pfs0dir=dir      Specify PFS0 directory path.\n\
  --outdir=dir       Specify PFS0 directory path. Overrides previous path, if present.\n\
  --exefsdir=dir     Specify PFS0 directory path. Overrides previous paths, if present for ExeFS PFS0.\n\
RomFS options:\n\
  --romfsdir=dir     Specify RomFS directory path.\n\
  --outdir=dir       Specify RomFS directory path. Overrides previous path, if present.\n\
  --listromfs        List files in RomFS.\n\
HFS0 options:\n\
  --hfs0dir=dir      Specify HFS0 directory path.\n\
  --outdir=dir       Specify HFS0 directory path. Overrides previous path, if present.\n\
  --exefsdir=dir     Specify HFS0 directory path. Overrides previous paths, if present.\n\
XCI options:\n\
  --rootdir=dir      Specify XCI root HFS0 directory path.\n\
  --updatedir=dir    Specify XCI update HFS0 directory path.\n\
  --normaldir=dir    Specify XCI normal HFS0 directory path.\n\
  --securedir=dir    Specify XCI secure HFS0 directory path.\n\
  --logodir=dir      Specify XCI logo HFS0 directory path.\n\
  --outdir=dir       Specify XCI directory path. Overrides previous paths, if present.\n\
Package1 options:\n\
  --package1dir=dir  Specify Package1 directory path.\n\
  --outdir=dir       Specify Package1 directory path. Overrides previous path, if present.\n\
Package2 options:\n\
  --package2dir=dir  Specify Package2 directory path.\n\
  --outdir=dir       Specify Package2 directory path. Overrides previous path, if present.\n\
  --extractini1      Enable INI1 extraction to default directory (redundant with --ini1dir set).\n\
  --ini1dir=dir      Specify INI1 directory path. Overrides default path, if present.\n\
INI1 options:\n\
  --ini1dir=dir      Specify INI1 directory path.\n\
  --outdir=dir       Specify INI1 directory path. Overrides previous path, if present.\n\
  --saveini1json     Enable generation of JSON descriptors for all INI1 members.\n\
NAX0 options:\n\
  --sdseed=seed      Set console unique seed for SD card NAX0 encryption.\n\
  --sdpath=path      Set relative path for NAX0 key derivation (ex: /registered/000000FF/cafebabecafebabecafebabecafebabe.nca).\n\
Save data options:\n\
  --outdir=dir       Specify save directory path.\n\
  --listfiles        List files in save file.\n\
Key Derivation options:\n\
  --sbk=key          Set console unique Secure Boot Key for key derivation.\n\
  --tseckey=key      Set console unique TSEC Key for key derivation.\n\
\n",
        prog_name
    );
    process::exit(1);
}

#[derive(Clone, Copy)]
enum OptId {
    Short(char),
    Long(u32),
}

fn get_long_option(name: &str) -> Option<(OptId, bool)> {
    match name {
        "extract" => Some((OptId::Short('x'), false)),
        "info" => Some((OptId::Short('i'), false)),
        "dev" => Some((OptId::Short('d'), false)),
        "verify" => Some((OptId::Short('y'), false)),
        "raw" => Some((OptId::Short('r'), false)),
        "quiet" => Some((OptId::Short('q'), false)),
        "intype" => Some((OptId::Short('t'), true)),
        "keyset" => Some((OptId::Short('k'), true)),
        "section0" => Some((OptId::Long(0), true)),
        "section1" => Some((OptId::Long(1), true)),
        "section2" => Some((OptId::Long(2), true)),
        "section3" => Some((OptId::Long(3), true)),
        "section0dir" => Some((OptId::Long(4), true)),
        "section1dir" => Some((OptId::Long(5), true)),
        "section2dir" => Some((OptId::Long(6), true)),
        "section3dir" => Some((OptId::Long(7), true)),
        "exefs" => Some((OptId::Long(8), true)),
        "romfs" => Some((OptId::Long(9), true)),
        "exefsdir" => Some((OptId::Long(10), true)),
        "romfsdir" => Some((OptId::Long(11), true)),
        "titlekey" => Some((OptId::Long(12), true)),
        "contentkey" => Some((OptId::Long(13), true)),
        "listromfs" => Some((OptId::Long(14), false)),
        "baseromfs" => Some((OptId::Long(15), true)),
        "basenca" => Some((OptId::Long(16), true)),
        "outdir" => Some((OptId::Long(17), true)),
        "plaintext" => Some((OptId::Long(18), true)),
        "header" => Some((OptId::Long(19), true)),
        "pfs0dir" => Some((OptId::Long(20), true)),
        "hfs0dir" => Some((OptId::Long(21), true)),
        "rootdir" => Some((OptId::Long(22), true)),
        "updatedir" => Some((OptId::Long(23), true)),
        "normaldir" => Some((OptId::Long(24), true)),
        "securedir" => Some((OptId::Long(25), true)),
        "logodir" => Some((OptId::Long(26), true)),
        "package1dir" => Some((OptId::Long(27), true)),
        "package2dir" => Some((OptId::Long(28), true)),
        "ini1dir" => Some((OptId::Long(29), true)),
        "extractini1" => Some((OptId::Long(30), false)),
        "basefake" => Some((OptId::Long(31), false)),
        "onlyupdated" => Some((OptId::Long(32), false)),
        "sdseed" => Some((OptId::Long(33), true)),
        "sdpath" => Some((OptId::Long(34), true)),
        "sbk" => Some((OptId::Long(35), true)),
        "tseckey" => Some((OptId::Long(36), true)),
        "json" => Some((OptId::Long(37), true)),
        "saveini1json" => Some((OptId::Long(38), false)),
        "uncompressed" => Some((OptId::Long(39), true)),
        "disablekeywarns" => Some((OptId::Long(40), false)),
        "listfiles" => Some((OptId::Long(41), false)),
        "xcontenttype" => Some((OptId::Long(42), true)),
        "appendsectypes" => Some((OptId::Long(43), false)),
        "suppresskeys" => Some((OptId::Long(44), false)),
        _ => None,
    }
}

fn handle_option(
    opt: OptId,
    optarg: Option<&str>,
    tool_ctx: &mut HactoolCtx,
    base_ctx: &mut HactoolCtx,
    keypath: &mut Filepath,
    has_base_file: &mut bool,
    prog_name: &str,
) {
    match opt {
        OptId::Short('i') => {
            tool_ctx.action |= ACTION_INFO;
        }
        OptId::Short('x') => {
            tool_ctx.action |= ACTION_EXTRACT;
        }
        OptId::Short('y') => {
            tool_ctx.action |= ACTION_VERIFY;
        }
        OptId::Short('r') => {
            tool_ctx.action |= ACTION_RAW;
        }
        OptId::Short('d') => {
            pki_initialize_keyset(&mut tool_ctx.settings.keyset, KeysetVariant::Dev);
            tool_ctx.action |= ACTION_DEV;
        }
        OptId::Short('q') => {
            tool_ctx.settings.quiet = true;
        }
        OptId::Short('k') => {
            keypath.set(optarg.unwrap_or(""));
        }
        OptId::Short('t') => {
            let arg = optarg.unwrap_or("");
            if arg == "nca" {
                tool_ctx.file_type = FileType::Nca;
            } else if arg == "pfs0" || arg == "exefs" {
                tool_ctx.file_type = FileType::Pfs0;
            } else if arg == "romfs" {
                tool_ctx.file_type = FileType::Romfs;
            } else if arg == "nca0_romfs"
                || arg == "nca0romfs"
                || arg == "betaromfs"
                || arg == "beta_romfs"
            {
                tool_ctx.file_type = FileType::Nca0Romfs;
            } else if arg == "hfs0" {
                tool_ctx.file_type = FileType::Hfs0;
            } else if arg == "xci" || arg == "gamecard" || arg == "gc" {
                tool_ctx.file_type = FileType::Xci;
            } else if arg == "npdm" || arg == "meta" {
                tool_ctx.file_type = FileType::Npdm;
            } else if arg == "package1" || arg == "pk11" {
                tool_ctx.file_type = FileType::Package1;
            } else if arg == "package2" || arg == "pk21" {
                tool_ctx.file_type = FileType::Package2;
            } else if arg == "ini1" {
                tool_ctx.file_type = FileType::Ini1;
            } else if arg == "kip1" || arg == "kip" {
                tool_ctx.file_type = FileType::Kip1;
            } else if arg == "nso0" || arg == "nso" {
                tool_ctx.file_type = FileType::Nso0;
            } else if arg == "nax0" || arg == "nax" {
                tool_ctx.file_type = FileType::Nax0;
            } else if arg == "keygen" || arg == "keys" || arg == "boot0" || arg == "boot" {
                tool_ctx.file_type = FileType::Boot0;
            } else if arg == "save" {
                tool_ctx.file_type = FileType::Save;
            }
        }
        OptId::Long(0) => tool_ctx.settings.section_paths[0].set(optarg.unwrap_or("")),
        OptId::Long(1) => tool_ctx.settings.section_paths[1].set(optarg.unwrap_or("")),
        OptId::Long(2) => tool_ctx.settings.section_paths[2].set(optarg.unwrap_or("")),
        OptId::Long(3) => tool_ctx.settings.section_paths[3].set(optarg.unwrap_or("")),
        OptId::Long(4) => tool_ctx.settings.section_dir_paths[0].set(optarg.unwrap_or("")),
        OptId::Long(5) => tool_ctx.settings.section_dir_paths[1].set(optarg.unwrap_or("")),
        OptId::Long(6) => tool_ctx.settings.section_dir_paths[2].set(optarg.unwrap_or("")),
        OptId::Long(7) => tool_ctx.settings.section_dir_paths[3].set(optarg.unwrap_or("")),
        OptId::Long(8) => {
            tool_ctx.settings.exefs_path.enabled = true;
            tool_ctx.settings.exefs_path.path.set(optarg.unwrap_or(""));
        }
        OptId::Long(9) => {
            tool_ctx.settings.romfs_path.enabled = true;
            tool_ctx.settings.romfs_path.path.set(optarg.unwrap_or(""));
        }
        OptId::Long(10) => {
            tool_ctx.settings.exefs_dir_path.enabled = true;
            tool_ctx
                .settings
                .exefs_dir_path
                .path
                .set(optarg.unwrap_or(""));
        }
        OptId::Long(11) => {
            tool_ctx.settings.romfs_dir_path.enabled = true;
            tool_ctx
                .settings
                .romfs_dir_path
                .path
                .set(optarg.unwrap_or(""));
        }
        OptId::Long(12) => {
            parse_hex_key(&mut tool_ctx.settings.cli_titlekey, optarg.unwrap_or(""));
            tool_ctx.settings.has_cli_titlekey = true;
        }
        OptId::Long(13) => {
            parse_hex_key(&mut tool_ctx.settings.cli_contentkey, optarg.unwrap_or(""));
            tool_ctx.settings.has_cli_contentkey = true;
        }
        OptId::Long(14) => {
            tool_ctx.action |= ACTION_LISTROMFS;
        }
        OptId::Long(15) => {
            if *has_base_file {
                usage(prog_name);
            }
            let arg = optarg.unwrap_or("");
            match File::open(arg) {
                Ok(f) => {
                    tool_ctx.base_file = Some(SharedFile::new(f));
                    tool_ctx.base_file_type = BaseFileType::Romfs;
                    *has_base_file = true;
                }
                Err(e) => {
                    eprintln!("unable to open {}: {}", arg, e);
                    process::exit(1);
                }
            }
        }
        OptId::Long(16) => {
            if *has_base_file {
                usage(prog_name);
            }
            let arg = optarg.unwrap_or("");
            match File::open(arg) {
                Ok(f) => {
                    let sf = SharedFile::new(f);
                    tool_ctx.base_file = Some(sf.clone());
                    tool_ctx.base_file_type = BaseFileType::Nca;
                    base_ctx.file = Some(sf.clone());
                    let mut b_nca = Box::new(NcaCtx::new());
                    b_nca.file = Some(sf);
                    b_nca.is_cli_target = false;
                    tool_ctx.base_nca_ctx = Some(b_nca);
                    *has_base_file = true;
                }
                Err(e) => {
                    eprintln!("unable to open {}: {}", arg, e);
                    process::exit(1);
                }
            }
        }
        OptId::Long(17) => {
            tool_ctx.settings.out_dir_path.enabled = true;
            tool_ctx
                .settings
                .out_dir_path
                .path
                .set(optarg.unwrap_or(""));
        }
        OptId::Long(18) => {
            tool_ctx.settings.plaintext_path.set(optarg.unwrap_or(""));
        }
        OptId::Long(19) => {
            tool_ctx.settings.header_path.set(optarg.unwrap_or(""));
        }
        OptId::Long(20) => {
            tool_ctx.settings.pfs0_dir_path.set(optarg.unwrap_or(""));
        }
        OptId::Long(21) => {
            tool_ctx.settings.hfs0_dir_path.set(optarg.unwrap_or(""));
        }
        OptId::Long(22) => {
            tool_ctx.settings.rootpt_dir_path.set(optarg.unwrap_or(""));
        }
        OptId::Long(23) => {
            tool_ctx.settings.update_dir_path.set(optarg.unwrap_or(""));
        }
        OptId::Long(24) => {
            tool_ctx.settings.normal_dir_path.set(optarg.unwrap_or(""));
        }
        OptId::Long(25) => {
            tool_ctx.settings.secure_dir_path.set(optarg.unwrap_or(""));
        }
        OptId::Long(26) => {
            tool_ctx.settings.logo_dir_path.set(optarg.unwrap_or(""));
        }
        OptId::Long(27) => {
            tool_ctx.settings.pk11_dir_path.set(optarg.unwrap_or(""));
        }
        OptId::Long(28) => {
            tool_ctx.settings.pk21_dir_path.set(optarg.unwrap_or(""));
        }
        OptId::Long(29) => {
            tool_ctx.settings.ini1_dir_path.set(optarg.unwrap_or(""));
        }
        OptId::Long(30) => {
            tool_ctx.action |= ACTION_EXTRACTINI1;
        }
        OptId::Long(31) => {
            if *has_base_file {
                usage(prog_name);
            }
            tool_ctx.base_file_type = BaseFileType::Fake;
            *has_base_file = true;
        }
        OptId::Long(32) => {
            tool_ctx.action |= ACTION_ONLYUPDATEDROMFS;
        }
        OptId::Long(33) => {
            parse_hex_key(&mut tool_ctx.settings.sdseed, optarg.unwrap_or(""));
            tool_ctx.settings.has_sdseed = true;
            for key in 0..2 {
                for i in 0..0x20 {
                    tool_ctx.settings.keyset.sd_card_key_sources[key][i] ^=
                        tool_ctx.settings.sdseed[i & 0xF];
                }
            }
            pki_derive_keys(&mut tool_ctx.settings.keyset);
        }
        OptId::Long(34) => {
            tool_ctx.settings.nax0_sd_path.set(optarg.unwrap_or(""));
        }
        OptId::Long(35) => {
            parse_hex_key(&mut tool_ctx.settings.keygen_sbk, optarg.unwrap_or(""));
        }
        OptId::Long(36) => {
            parse_hex_key(&mut tool_ctx.settings.keygen_tsec, optarg.unwrap_or(""));
        }
        OptId::Long(37) => {
            tool_ctx.settings.npdm_json_path.set(optarg.unwrap_or(""));
        }
        OptId::Long(38) => {
            tool_ctx.action |= ACTION_SAVEINIJSON;
        }
        OptId::Long(39) => {
            tool_ctx
                .settings
                .uncompressed_path
                .set(optarg.unwrap_or(""));
        }
        OptId::Long(40) => {
            tool_ctx.settings.skip_key_warnings = true;
        }
        OptId::Long(41) => {
            tool_ctx.action |= ACTION_LISTFILES;
        }
        OptId::Long(42) => {
            let arg = optarg.unwrap_or("");
            if !arg.is_empty() {
                tool_ctx.settings.has_expected_content_type = true;
                if arg.eq_ignore_ascii_case("program") {
                    tool_ctx.settings.expected_content_type = NCACONTENTTYPE_PROGRAM;
                } else if arg.eq_ignore_ascii_case("meta") {
                    tool_ctx.settings.expected_content_type = NCACONTENTTYPE_META;
                } else if arg.eq_ignore_ascii_case("control") {
                    tool_ctx.settings.expected_content_type = NCACONTENTTYPE_CONTROL;
                } else if arg.eq_ignore_ascii_case("manual") {
                    tool_ctx.settings.expected_content_type = NCACONTENTTYPE_MANUAL;
                } else if arg.eq_ignore_ascii_case("data") {
                    tool_ctx.settings.expected_content_type = NCACONTENTTYPE_DATA;
                } else if arg.eq_ignore_ascii_case("publicdata") {
                    tool_ctx.settings.expected_content_type = NCACONTENTTYPE_PUBLICDATA;
                } else if arg.as_bytes()[0] >= b'0'
                    && arg.as_bytes().get(1).copied().unwrap_or(0) <= b'9'
                {
                    tool_ctx.settings.expected_content_type = (arg.as_bytes()[0] - b'0') as u32;
                } else {
                    println!("[WARN] Unknown expected content type ({}).", arg);
                    tool_ctx.settings.has_expected_content_type = false;
                }
            }
        }
        OptId::Long(43) => {
            tool_ctx.settings.append_section_types = true;
        }
        OptId::Long(44) => {
            tool_ctx.settings.suppress_keydata_output = true;
        }
        _ => {
            usage(prog_name);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let prog_name = args.first().map(|s| s.as_str()).unwrap_or("hactool");

    let mut tool_ctx = HactoolCtx::new();
    let mut base_ctx = HactoolCtx::new();
    let mut nca_ctx = NcaCtx::new();
    let mut keypath = Filepath::new();
    let mut has_base_file = false;

    nca_ctx.is_cli_target = true;
    tool_ctx.file_type = FileType::Nca;
    base_ctx.file_type = FileType::Nca;
    tool_ctx.action = ACTION_INFO | ACTION_EXTRACT;
    pki_initialize_keyset(&mut tool_ctx.settings.keyset, KeysetVariant::Retail);

    let mut positional_args: Vec<String> = Vec::new();
    let mut idx = 1usize;
    let mut stop_options = false;

    while idx < args.len() {
        let arg = &args[idx];
        if stop_options || !arg.starts_with('-') || arg == "-" {
            positional_args.push(arg.clone());
            idx += 1;
            continue;
        }
        if arg == "--" {
            stop_options = true;
            idx += 1;
            continue;
        }
        if let Some(long_part) = arg.strip_prefix("--") {
            let (name, inline_val) = match long_part.find('=') {
                Some(eq_pos) => (&long_part[..eq_pos], Some(&long_part[eq_pos + 1..])),
                None => (long_part, None),
            };
            let (opt_id, takes_arg) = match get_long_option(name) {
                Some(x) => x,
                None => usage(prog_name),
            };
            let optarg = if takes_arg {
                if let Some(v) = inline_val {
                    Some(v)
                } else {
                    idx += 1;
                    if idx >= args.len() {
                        usage(prog_name);
                    }
                    Some(args[idx].as_str())
                }
            } else {
                if inline_val.is_some() {
                    usage(prog_name);
                }
                None
            };
            handle_option(
                opt_id,
                optarg,
                &mut tool_ctx,
                &mut base_ctx,
                &mut keypath,
                &mut has_base_file,
                prog_name,
            );
            idx += 1;
        } else {
            // Short options cluster: e.g. -d, -r, -y, -x, -t<val>, -i, -k<val>
            let chars: Vec<char> = arg[1..].chars().collect();
            let mut c_idx = 0usize;
            while c_idx < chars.len() {
                let c = chars[c_idx];
                match c {
                    'd' | 'r' | 'y' | 'x' | 'i' | 'q' => {
                        handle_option(
                            OptId::Short(c),
                            None,
                            &mut tool_ctx,
                            &mut base_ctx,
                            &mut keypath,
                            &mut has_base_file,
                            prog_name,
                        );
                        c_idx += 1;
                    }
                    't' | 'k' => {
                        let rest: String = chars[c_idx + 1..].iter().collect();
                        let val_str = if !rest.is_empty() {
                            rest
                        } else {
                            idx += 1;
                            if idx >= args.len() {
                                usage(prog_name);
                            }
                            args[idx].clone()
                        };
                        handle_option(
                            OptId::Short(c),
                            Some(&val_str),
                            &mut tool_ctx,
                            &mut base_ctx,
                            &mut keypath,
                            &mut has_base_file,
                            prog_name,
                        );
                        break;
                    }
                    _ => usage(prog_name),
                }
            }
            idx += 1;
        }
    }

    // Try to populate default keyfile
    let mut keyfile: Option<File> = None;
    if keypath.valid == Validity::Valid {
        keyfile = File::open(&keypath.char_path).ok();
    }
    let homekeyfile = open_key_file(if (tool_ctx.action & ACTION_DEV) != 0 {
        "dev"
    } else {
        "prod"
    });
    if homekeyfile.is_none() {
        println!(
            "[WARN] {}.keys does not exist.",
            if (tool_ctx.action & ACTION_DEV) != 0 {
                "dev"
            } else {
                "prod"
            }
        );
    } else if keyfile.is_none() {
        keyfile = homekeyfile;
    }

    if let Some(kf) = keyfile {
        extkeys_initialize_settings(&mut tool_ctx.settings, kf);
        if tool_ctx.settings.has_sdseed {
            for key in 0..2 {
                for i in 0..0x20 {
                    tool_ctx.settings.keyset.sd_card_key_sources[key][i] ^=
                        tool_ctx.settings.sdseed[i & 0xF];
                }
            }
        }
        pki_derive_keys(&mut tool_ctx.settings.keyset);
    }

    // Try to load titlekeys
    if let Some(tkf) = open_key_file("title") {
        extkeys_parse_titlekeys(&mut tool_ctx.settings, tkf);
    }

    let mut input_name = String::new();
    if positional_args.len() == 1 {
        input_name = positional_args[0].clone();
    } else if tool_ctx.file_type != FileType::Boot0
        && (!positional_args.is_empty() || args.len() == 1)
    {
        usage(prog_name);
    }

    // Special case NAX0
    if tool_ctx.file_type == FileType::Nax0 {
        let mut nax_ctx = Nax0Ctx::default();
        nax_ctx.base_path.set(&input_name);
        nax0_process(&mut nax_ctx, &tool_ctx);
        println!("Done!");
        return;
    }

    if !input_name.is_empty() {
        match File::open(&input_name) {
            Ok(f) => {
                tool_ctx.file = Some(SharedFile::new(f));
            }
            Err(e) => {
                if tool_ctx.file_type != FileType::Boot0 {
                    eprintln!("unable to open {}: {}", input_name, e);
                    process::exit(1);
                }
            }
        }
    } else if tool_ctx.file_type != FileType::Boot0 {
        eprintln!("unable to open : No such file or directory");
        process::exit(1);
    }

    match tool_ctx.file_type {
        FileType::Nca => {
            if let Some(mut b_nca) = tool_ctx.base_nca_ctx.take() {
                base_ctx.settings.keyset = tool_ctx.settings.keyset.clone();
                base_ctx.settings.known_titlekeys = tool_ctx.settings.known_titlekeys.clone();
                nca_process(&mut b_nca, &mut base_ctx);
                let mut found_romfs = false;
                for i in 0..4 {
                    if b_nca.section_contexts[i].is_present
                        && b_nca.section_contexts[i].section_type == NcaSectionType::Romfs
                    {
                        found_romfs = true;
                        break;
                    }
                }
                if !found_romfs {
                    eprintln!("Unable to locate RomFS in base NCA!");
                    process::exit(1);
                }
                tool_ctx.base_nca_ctx = Some(b_nca);
            }

            nca_ctx.file = tool_ctx.file.clone();
            nca_process(&mut nca_ctx, &mut tool_ctx);
        }
        FileType::Pfs0 => {
            let mut pfs0_ctx = Pfs0Ctx::new();
            pfs0_ctx.file = tool_ctx.file.clone();
            pfs0_process(&mut pfs0_ctx, &mut tool_ctx);
        }
        FileType::Romfs => {
            let mut romfs_ctx = RomfsCtx::default();
            romfs_ctx.file = tool_ctx.file.clone();
            romfs_process(&mut romfs_ctx, &mut tool_ctx);
        }
        FileType::Nca0Romfs => {
            let mut romfs_ctx = Nca0RomfsCtx::default();
            romfs_ctx.file = tool_ctx.file.clone();
            nca0_romfs_process(&mut romfs_ctx, &mut tool_ctx);
        }
        FileType::Npdm => {
            let file = tool_ctx.file.as_ref().unwrap();
            let mut raw_hdr_bytes = [0u8; NPDM_HEADER_SIZE];
            if file.read_exact_at(0, &mut raw_hdr_bytes).is_err() {
                eprintln!("Failed to read NPDM header!");
                process::exit(1);
            }
            let raw_hdr = NpdmHeader::from_bytes(&raw_hdr_bytes);
            if raw_hdr.magic != MAGIC_META {
                eprintln!("NPDM seems corrupt!");
                process::exit(1);
            }
            let mut npdm_size = (raw_hdr.aci0_size + raw_hdr.aci0_offset) as usize;
            let acid_end = (raw_hdr.acid_offset + raw_hdr.acid_size) as usize;
            if acid_end > npdm_size {
                npdm_size = acid_end;
            }
            let mut npdm_bytes = vec![0u8; npdm_size];
            if file.read_exact_at(0, &mut npdm_bytes).is_err() {
                eprintln!("Failed to read NPDM!");
                process::exit(1);
            }
            npdm_process(&npdm_bytes, &mut tool_ctx);
        }
        FileType::Hfs0 => {
            let mut hfs0_ctx = Hfs0Ctx::new();
            hfs0_ctx.file = tool_ctx.file.clone();
            hfs0_process(&mut hfs0_ctx, &mut tool_ctx);
        }
        FileType::Package1 => {
            let mut pk11_ctx = Pk11Ctx::default();
            pk11_ctx.file = tool_ctx.file.clone();
            pk11_process(&mut pk11_ctx, &tool_ctx);
        }
        FileType::Package2 => {
            let mut pk21_ctx = Pk21Ctx::default();
            pk21_ctx.file = tool_ctx.file.clone();
            pk21_process(&mut pk21_ctx, &mut tool_ctx);
        }
        FileType::Ini1 => {
            let mut ini1_ctx = Ini1Ctx::default();
            ini1_ctx.file = tool_ctx.file.clone();
            ini1_process(&mut ini1_ctx, &tool_ctx);
        }
        FileType::Kip1 => {
            let mut kip1_ctx = Kip1Ctx::default();
            kip1_ctx.file = tool_ctx.file.clone();
            kip1_process(&mut kip1_ctx, &tool_ctx);
        }
        FileType::Nso0 => {
            let mut nso0_ctx = Nso0Ctx::default();
            nso0_ctx.file = tool_ctx.file.clone();
            nso0_process(&mut nso0_ctx, &tool_ctx);
        }
        FileType::Xci => {
            let mut xci_ctx = XciCtx::default();
            xci_ctx.file = tool_ctx.file.clone();
            xci_process(&mut xci_ctx, &mut tool_ctx);
        }
        FileType::Boot0 => {
            let mut new_keyset = tool_ctx.settings.keyset.clone();
            if tool_ctx.settings.keygen_sbk.iter().any(|&b| b != 0) {
                new_keyset
                    .secure_boot_key
                    .copy_from_slice(&tool_ctx.settings.keygen_sbk);
            }
            if tool_ctx.settings.keygen_tsec.iter().any(|&b| b != 0) {
                new_keyset
                    .tsec_key
                    .copy_from_slice(&tool_ctx.settings.keygen_tsec);
            }
            if let Some(ref f) = tool_ctx.file {
                for i in 0..0x20 {
                    let off = 0x180000 + 0x200 * (i as u64);
                    if f.read_exact_at(off, &mut new_keyset.encrypted_keyblobs[i])
                        .is_err()
                    {
                        eprintln!("Error: Failed to read encrypted_keyblob_{:02x} from boot0!", i);
                        process::exit(1);
                    }
                }
            }
            println!("Deriving keys...");
            pki_derive_keys(&mut new_keyset);
            println!("--");
            println!("All derivable keys (using loaded sources):\n");
            pki_print_keys(&new_keyset);
        }
        FileType::Save => {
            let mut save_ctx = SaveCtx::default();
            save_ctx.file = tool_ctx.file.clone();
            save_process(&mut save_ctx, &tool_ctx);
        }
        FileType::Nax0 => {}
    }

    println!("Done!");
}
