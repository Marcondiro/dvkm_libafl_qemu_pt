use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::{ProgressReporter, SimpleEventManager},
    executors::ExitKind,
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{havoc_mutations, StdScheduledMutator},
    observers::{StdMapObserver, TimeObserver},
    schedulers::QueueScheduler,
    stages::StdMutationalStage,
    state::{HasSolutions, StdState},
    Fuzzer, StdFuzzer,
};
use libafl_bolts::{current_nanos, rands::StdRand, tuples::tuple_list};
use libafl_qemu::{
    config::{self, Accelerator, Drive, Monitor, QemuConfig, RamSize},
    modules::intel_pt::{IntelPTModule, SectionInfo},
    Emulator, EmulatorBuilder, GuestAddr, QemuExecutor, QemuExitReason,
};
use std::{
    env, fs,
    num::NonZero,
    path::{Path, PathBuf},
    time::Duration,
};

const INPUT_SIZE: usize = 1024;
const INPUT_ADDRESS: GuestAddr = 0x404060;

const NEEDLE_STOP_FUZZER: GuestAddr = 0xbbaa00;

// Coverage map
const MAP_SIZE: usize = 256;
static mut MAP: [u16; MAP_SIZE] = [0; MAP_SIZE];

fn main() {
    env_logger::init();

    let timeout = Duration::from_secs(4);
    let objective_dir = PathBuf::from("./crashes");
    let target_dir = env::var("TARGET_DIR").unwrap_or("target".to_string());

    let mon = SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr = SimpleEventManager::new(mon);

    let qemu_config = QemuConfig::builder()
        .kernel(format!("{target_dir}/linux/arch/x86_64/boot/bzImage"))
        .initrd("target/initrd.img")
        .accelerator(Accelerator::Kvm)
        .no_graphic(true)
        .default_devices(false)
        .monitor(Monitor::Tcp(
            config::Tcp::builder()
                .port(4444)
                .server(true)
                .wait(false)
                .build(),
        ))
        .serial(config::Serial::Tcp(
            config::Tcp::builder()
                .port(4445)
                .server(true)
                .wait(false)
                .build(),
        ))
        .cpu("host")
        .ram_size(RamSize::GB(1))
        .drives([Drive::builder().file("./target/dvkm.qcow2").build()])
        .start_cpu(false)
        .load_vm("pre_fuzz")
        .machine("pc-i440fx-8.2")
        .bios("/usr/share/seabios")
        .build();

    let virtual_address_raw = fs::read(Path::new("target/sections/.text")).unwrap();
    let virtual_address = u64::from_str_radix(
        String::from_utf8(virtual_address_raw)
            .unwrap()
            .trim()
            .trim_start_matches("0x"),
        16,
    )
    .unwrap();
    let image = [SectionInfo {
        filename: "./target/dump.bin".to_owned(),
        offset: 0,
        size: 0x1000,
        virtual_address,
    }];

    let filter = image
        .iter()
        .map(|s| s.virtual_address as usize..=(s.virtual_address + s.size) as usize)
        .collect::<Vec<_>>();

    let intel_pt_builder = IntelPTModule::default_pt_builder().ip_filters(&filter);
    let emulator_modules = tuple_list!(IntelPTModule::builder()
        .map_ptr(unsafe { MAP.as_mut_ptr() })
        .map_len(MAP_SIZE)
        .intel_pt_builder(intel_pt_builder)
        .image(&image)
        .build());

    let emulator = EmulatorBuilder::empty()
        .qemu_parameters(qemu_config)
        .modules(emulator_modules)
        .build()
        .unwrap();
    let qemu = emulator.qemu();

    qemu.set_hw_breakpoint(NEEDLE_STOP_FUZZER).unwrap();

    let oops_exit_raw = fs::read(Path::new("target/kallsyms/oops_exit")).unwrap();
    let oops_exit = GuestAddr::from_str_radix(
        String::from_utf8(oops_exit_raw)
            .unwrap()
            .trim()
            .trim_start_matches("0x"),
        16,
    )
    .unwrap();
    let kasan_report_raw = fs::read(Path::new("target/kallsyms/kasan_report")).unwrap();
    let kasan_report = u64::from_str_radix(
        String::from_utf8(kasan_report_raw)
            .unwrap()
            .trim()
            .trim_start_matches("0x"),
        16,
    )
    .unwrap();

    // TODO use the correct address from files
    qemu.set_hw_breakpoint(oops_exit).unwrap();
    qemu.set_hw_breakpoint(kasan_report).unwrap();

    let mut harness = |emulator: &mut Emulator<_, _, _, _, _, _, _>,
                       _: &mut StdState<_, _, _, _>,
                       input: &BytesInput| unsafe {
        let truncated_input = if input.target_bytes().len() > INPUT_SIZE {
            &input.target_bytes()[..INPUT_SIZE]
        } else {
            &input.target_bytes()
        };

        qemu.load_snapshot("pre_fuzz", true);
        qemu.write_mem(INPUT_ADDRESS, truncated_input).unwrap();
        match emulator.qemu().run() {
            Ok(QemuExitReason::Breakpoint(NEEDLE_STOP_FUZZER)) => ExitKind::Ok,
            Ok(QemuExitReason::Breakpoint(bp)) if bp == oops_exit || bp == kasan_report => {
                ExitKind::Crash
            }
            e => panic!("Harness Unexpected QEMU exit. {e:x?}"),
        }
    };

    // Create an observation channel using the map
    let observer = unsafe { StdMapObserver::from_mut_ptr("signals", MAP.as_mut_ptr(), MAP_SIZE) };

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        MaxMapFeedback::new(&observer),
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new(&time_observer)
    );

    // A feedback to choose if an input is a solution or not
    let mut objective = feedback_or_fast!(CrashFeedback::new());

    // If not restarting, create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::new(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(objective_dir.clone()).unwrap(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();

    // A queue policy to get testcases from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Create a QEMU in-process executor
    let mut executor = QemuExecutor::new(
        emulator,
        &mut harness,
        tuple_list!(observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        timeout,
    )
    .expect("Failed to create QemuExecutor");

    // Generator of printable bytearrays of max size 10
    let mut generator = RandPrintablesGenerator::new(NonZero::new(10).unwrap());

    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 4)
        .expect("Failed to generate the initial corpus");

    // Setup an havoc mutator with a mutational stage
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    while state.solutions().is_empty() {
        mgr.maybe_report_progress(&mut state, Duration::from_secs(5))
            .unwrap();

        fuzzer
            .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("Error in the fuzzing loop");
    }
}
