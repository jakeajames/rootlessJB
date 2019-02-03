//
//  ViewController.m
//  rootlessJB
//
//  Created by Jake James on 8/28/18.
//  Copyright © 2018 Jake James. All rights reserved.
//

#import "ViewController.h"
#import "jelbrekLib.h"
#import "exploit/multi_path/sploit.h"
#import "exploit/voucher_swap/voucher_swap.h"
#import "libjb.h"
#import "payload.h"
#import "offsetsDump.h"
#import "exploit/voucher_swap/kernel_slide.h"

#import <mach/mach.h>
#import <sys/stat.h>

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UISwitch *enableTweaks;
@property (weak, nonatomic) IBOutlet UIButton *jailbreakButton;
@property (weak, nonatomic) IBOutlet UISwitch *installiSuperSU;

@property (weak, nonatomic) IBOutlet UITextView *logs;
@end

@implementation ViewController

-(void)log:(NSString*)log {
    self.logs.text = [NSString stringWithFormat:@"%@%@", self.logs.text, log];
}

/*#define LOG(what, ...) dispatch_async(dispatch_get_main_queue(), ^{ \
                           [self log:[NSString stringWithFormat:@what"\n", ##__VA_ARGS__]];\
                           printf("\t"what"\n", ##__VA_ARGS__);\
                       })*/

#define LOG(what, ...) [self log:[NSString stringWithFormat:@what"\n", ##__VA_ARGS__]];\
                        printf("\t"what"\n", ##__VA_ARGS__)

#define in_bundle(obj) strdup([[[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:@obj] UTF8String])

#define failIf(condition, message, ...) if (condition) {\
                                            LOG(message);\
                                            goto end;\
                                        }
#define maxVersion(v)  ([[[UIDevice currentDevice] systemVersion] compare:@v options:NSNumericSearch] != NSOrderedDescending)


#define fileExists(file) [[NSFileManager defaultManager] fileExistsAtPath:@(file)]
#define removeFile(file) if (fileExists(file)) {\
                            [[NSFileManager defaultManager]  removeItemAtPath:@file error:&error]; \
                            if (error) { \
                                LOG("[-] Error: removing file %s (%s)", file, [[error localizedDescription] UTF8String]); \
                                error = NULL; \
                            }\
                         }

#define copyFile(copyFrom, copyTo) [[NSFileManager defaultManager] copyItemAtPath:@(copyFrom) toPath:@(copyTo) error:&error]; \
                                   if (error) { \
                                       LOG("[-] Error copying item %s to path %s (%s)", copyFrom, copyTo, [[error localizedDescription] UTF8String]); \
                                       error = NULL; \
                                   }

#define moveFile(copyFrom, moveTo) [[NSFileManager defaultManager] moveItemAtPath:@(copyFrom) toPath:@(moveTo) error:&error]; \
                                   if (error) {\
                                       LOG("[-] Error moviing item %s to path %s (%s)", copyFrom, moveTo, [[error localizedDescription] UTF8String]); \
                                       error = NULL; \
                                   }

- (void)viewDidLoad {
    [super viewDidLoad];
    if (!maxVersion("11.4.1") && maxVersion("12.1.2")) {
        [[self enableTweaks] setOn:false];
        [[self enableTweaks] setEnabled:false];
        [[self installiSuperSU] setOn:false];
        [[self installiSuperSU] setEnabled:false];
    }
    // Do any additional setup after loading the view, typically from a nib.
}

- (IBAction)jailbrek:(id)sender {
    
    //---- tfp0 ----//
    mach_port_t taskforpidzero = MACH_PORT_NULL;
    
    uint64_t sb = 0;
    BOOL debug = NO; // kids don't enable this
    
    // for messing with files
    NSError *error = NULL;
    NSArray *plists;
    
    if (debug) {
        kern_return_t ret = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &taskforpidzero);
        if (ret) {
            printf("[-] Error using hgsp! '%s'\n", mach_error_string(ret));
            printf("[*] Using exploit!\n");
            
            if (!maxVersion("11.4.1") && maxVersion("12.1.2")) {
                taskforpidzero = voucher_swap();
            }
            else if (maxVersion("11.3.1")) {
                taskforpidzero = exploit();
            }
            
            if (!MACH_PORT_VALID(taskforpidzero)) {
                LOG("[-] Exploit failed");
                LOG("[i] Please try again");
                sleep(1);
                return;
            }
        }
    }
    else {
        if (!maxVersion("11.4.1") && maxVersion("12.1.2")) {
            taskforpidzero = voucher_swap();
        }
        else if (maxVersion("11.3.1")) {
            taskforpidzero = exploit();
        }
        else {
            LOG("[-] Not supported");
            return;
        }
        if (!MACH_PORT_VALID(taskforpidzero)) {
            LOG("[-] Exploit failed");
            LOG("[i] Please try again");
            sleep(1);
            return;
        }
    }
    
    LOG("[*] Starting fun");
    if (!maxVersion("11.4.1") && maxVersion("12.1.2")) {
        kernel_slide_init();
        init_with_kbase(taskforpidzero, 0xfffffff007004000 + kernel_slide);
    }
    else if (maxVersion("11.3.1")) {
        init_jelbrek(taskforpidzero);
    }
   
    LOG("[i] Kernel base: 0x%llx", KernelBase);
    
    //---- basics ----//
    rootify(getpid()); // give us root
    failIf(getuid(), "[-] Failed to get root");
    LOG("[i] uid: %d\n", getuid());
    
    sb = unsandbox(getpid()); // escape sandbox
    FILE *f = fopen("/var/mobile/.roottest", "w");
    failIf(!f, "[-] Failed to escape sandbox!");
    
    LOG("[+] Escaped sandbox!\n\tWrote file %p", f);
    fclose(f);
    removeFile("/var/mobile/.roottest");
    
    setcsflags(getpid()); // set some csflags
    platformize(getpid()); // set TF_PLATFORM
    
    //---- host special port 4 ----//
    failIf(setHSP4(), "[-] Failed to set tfp0 as hsp4!");
    if (debug) PatchHostPriv(mach_host_self());
    
    //---- remount -----//
    // this is against the point of this jb but if you can why not do it
    
    if (maxVersion("11.4.1")) {
        if (remountRootFS()) LOG("[-] Failed to remount rootfs, no big deal");
    }
    
    //---- nvram ----//
    // people say that this ain't stable
    // and that ya should lock it later
    // but, I haven't experienced issues
    // nor so rootlessJB people
    
    UnlockNVRAM(); // use nvram command for nonce setting!
    
    //---- bootstrap ----//
    if (!fileExists("/var/containers/Bundle/iosbinpack64")) {
        LOG("[*] Installing bootstrap...");
        
        chdir("/var/containers/Bundle/");
        FILE *bootstrap = fopen((char*)in_bundle("tars/iosbinpack.tar"), "r");
        untar(bootstrap, "/var/containers/Bundle/");
        fclose(bootstrap);
        
        FILE *tweaks = fopen((char*)in_bundle("tars/tweaksupport.tar"), "r");
        untar(tweaks, "/var/containers/Bundle/");
        fclose(tweaks);
        
        failIf(!fileExists("/var/containers/Bundle/tweaksupport") || !fileExists("/var/containers/Bundle/iosbinpack64"), "[-] Failed to install bootstrap");
        
        LOG("[+] Creating symlinks...");
        
        symlink("/var/containers/Bundle/tweaksupport/Library", "/var/LIB");
        symlink("/var/containers/Bundle/tweaksupport/usr/lib", "/var/ulb");
        symlink("/var/containers/Bundle/tweaksupport/bin", "/var/bin");
        symlink("/var/containers/Bundle/tweaksupport/sbin", "/var/sbin");
        
        LOG("[+] Installed bootstrap!");
    }
    
    //---- for jailbreakd & amfid ----//
    if (maxVersion("11.4.1")) {
        failIf(dumpOffsetsToFile("/var/containers/Bundle/tweaksupport/offsets.data"), "[-] Failed to save offsets");
    }
    
    //---- amfid patch ----//
    chmod(in_bundle("bins/tester"), 0777); //give it proper permissions
    chmod(in_bundle("bins/test"), 0777);
    
    if (launch(in_bundle("bins/tester"), NULL, NULL, NULL, NULL, NULL, NULL, NULL)) {
        
        if (maxVersion("11.4.1")) {
            // patch amfid
            failIf(trustbin(in_bundle("dylibs/amfid_payload.dylib")), "[-] Failed to trust amfid payload"); // add amfid_payload to trustcache since amfid itself can't validate it when it's purpose is making amfid validate it
            
            // get amfid's pid
            pid_t amfid = pid_of_procName("amfid");
            failIf(!amfid, "[-] Failed to get amfid's pid");
            
            // entitle it
            failIf(!setcsflags(amfid), "[-] Failed to entitle amfid");
            failIf(!entitlePidOnAMFI(amfid, "get-task-allow", true), "[-] Failed to entitle amfid");
            failIf(!entitlePidOnAMFI(amfid, "com.apple.private.skip-library-validation", true), "[-] Failed to entitle amfid");
            
            // entitle ourselves too
            failIf(!entitlePidOnAMFI(getpid(), "task_for_pid-allow", true), "[-] Failed to entitle myself");
            failIf(!entitlePidOnAMFI(getpid(), "com.apple.system-task-ports", true), "[-] Failed to entitle myself");
            
            // inject
            failIf(inject_dylib(amfid, in_bundle("dylibs/amfid_payload.dylib")), "[-] Failed to inject code into amfid!");
            
            // test
            int ret = launch(in_bundle("bins/test"), NULL, NULL, NULL, NULL, NULL, NULL, NULL);
            failIf(ret, "[-] Failed to patch amfid!");
            LOG("[+] Successfully patched amfid!");
        }
        else if (maxVersion("12.1.2")){
            LOG("[*] iOS 12 detected. Not patching amfid.");
        }
    }
    else {
        LOG("[+] codesign already patched?");
    }
    
    //---- update bootstrap ----//
    // bootstrap has old files and updating that means start jb from scratch
    // this is less clean but works better and easier
    
    removeFile("/var/containers/Bundle/dylibs");
    copyFile(in_bundle("/dylibs"), "/var/containers/Bundle/dylibs");
    
    if (fileExists("/var/containers/Bundle/iosbinpack64/bin/launchctl_")) {
        failIf(!fileExists("/var/containers/Bundle/iosbinpack64/bin/launchctl"), "[-] Ouch! Only one launchctl?, I'm confused");
        removeFile("/var/containers/Bundle/iosbinpack64/bin/launchctl");
        copyFile("/var/containers/Bundle/iosbinpack64/bin/launchctl_", "/var/containers/Bundle/iosbinpack64/bin/launchctl");
    }
    
    if (!fileExists("/var/containers/Bundle/tweaksupport/Applications")) {
        mkdir("/var/containers/Bundle/tweaksupport/Applications", 777);
        if (!fileExists("/var/Apps")) {
            symlink("/var/containers/Bundle/tweaksupport/Applications", "/var/Apps");
        }
    }
    // update bins
    removeFile("/var/containers/Bundle/tweaksupport/bin/jailbreakd");
    removeFile("/var/containers/Bundle/tweaksupport/usr/bin/uicache");
    removeFile("/var/containers/Bundle/tweaksupport/usr/bin/inject_dylib");
    removeFile("/var/containers/Bundle/tweaksupport/usr/bin/inject");
    
    // pref loader
    removeFile("/var/containers/Bundle/tweaksupport/Library/TweakInject/PreferenceLoader.dylib");
    removeFile("/var/containers/Bundle/tweaksupport/usr/lib/libprefs.dylib");
    // TweakInject
    removeFile("/var/containers/Bundle/tweaksupport/usr/lib/TweakInject.dylib");
    // AppSync
    removeFile("/var/containers/Bundle/tweaksupport/usr/lib/TweakInject/AppSyncUnified.dylib");
    removeFile("/var/containers/Bundle/tweaksupport/usr/lib/TweakInject/AppSyncUnified.plist");
    
    // update
    copyFile(in_bundle("bins/jailbreakd"), "/var/containers/Bundle/tweaksupport/bin/jailbreakd");
    copyFile(in_bundle("bins/uicache"), "/var/containers/Bundle/tweaksupport/usr/bin/uicache");
    copyFile(in_bundle("bins/inject_dylib"), "/var/containers/Bundle/tweaksupport/usr/bin/inject_dylib");
    copyFile(in_bundle("bins/inject"), "/var/containers/Bundle/tweaksupport/usr/bin/inject");
    
    trustbin("/var/containers/Bundle/tweaksupport/usr/bin/inject_dylib");
    
    copyFile("/var/containers/Bundle/dylibs/PreferenceLoader.dylib", "/var/containers/Bundle/tweaksupport/Library/TweakInject/PreferenceLoader.dylib");
    copyFile("/var/containers/Bundle/dylibs/libprefs.dylib", "/var/containers/Bundle/tweaksupport/usr/lib/libprefs.dylib");
    
    copyFile("/var/containers/Bundle/dylibs/TweakInject.dylib", "/var/containers/Bundle/tweaksupport/usr/lib/TweakInject.dylib");

    copyFile("/var/containers/Bundle/dylibs/AppSyncUnified.dylib", "/var/containers/Bundle/tweaksupport/usr/lib/TweakInject/AppSyncUnified.dylib");
    copyFile("/var/containers/Bundle/dylibs/AppSyncUnified.plist", "/var/containers/Bundle/tweaksupport/usr/lib/TweakInject/AppSyncUnified.plist");
    
    if (!maxVersion("11.4.1") && maxVersion("12.1.2")) {
        failIf(trustbin("/var/containers/Bundle/tweaksupport"), "[-] Failed to trust libs!");
        failIf(trustbin("/var/containers/Bundle/iosbinpack64"), "[-] Failed to trust binaries!");
    }
    
    prepare_payload(); // this will chmod 777 everything
    
    //----- setup SSH -----//
    mkdir("/var/dropbear", 0777);
    removeFile("/var/profile");
    removeFile("/var/motd");
    chmod("/var/profile", 0777);
    chmod("/var/motd", 0777); //this can be read-only but just in case
    copyFile("/var/containers/Bundle/iosbinpack64/etc/profile", "/var/profile");
    copyFile("/var/containers/Bundle/iosbinpack64/etc/motd", "/var/motd");
    
    // kill it if running
    launch("/var/containers/Bundle/iosbinpack64/usr/bin/killall", "-SEGV", "dropbear", NULL, NULL, NULL, NULL, NULL);
    failIf(launchAsPlatform("/var/containers/Bundle/iosbinpack64/usr/local/bin/dropbear", "-R", "--shell", "/var/containers/Bundle/iosbinpack64/bin/bash", "-E", "-p", "22", NULL), "[-] Failed to launch dropbear");
    
    //------------- launch daeamons -------------//
    //--you can drop any daemon plist in iosbinpack64/LaunchDaemons and it will be loaded automatically--//
    
    if (maxVersion("11.4.1")) failIf(trustbin("/var/containers/Bundle/iosbinpack64/bin/launchctl"), "[-] Failed to trust launchctl");

    plists = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/var/containers/Bundle/iosbinpack64/LaunchDaemons" error:nil];
    
    for (__strong NSString *file in plists) {
        printf("[*] Adding permissions to plist %s\n", [file UTF8String]);
        
        file = [@"/var/containers/Bundle/iosbinpack64/LaunchDaemons" stringByAppendingPathComponent:file];
        
        if (strstr([file UTF8String], "jailbreakd")) {
            printf("[*] Found jailbreakd plist, special handling\n");
            
            NSMutableDictionary *job = [NSPropertyListSerialization propertyListWithData:[NSData dataWithContentsOfFile:file] options:NSPropertyListMutableContainers format:nil error:nil];
            
            job[@"EnvironmentVariables"][@"KernelBase"] = [NSString stringWithFormat:@"0x%16llx", KernelBase];
            [job writeToFile:file atomically:YES];
            
            if (!maxVersion("11.4.1") && maxVersion("12.1.2")) {
                [[NSFileManager defaultManager] removeItemAtPath:file error:nil];
            }
        }
        
        chmod([file UTF8String], 0644);
        chown([file UTF8String], 0, 0);
    }
    
    // clean up
    removeFile("/var/log/testbin.log");
    removeFile("/var/log/jailbreakd-stderr.log");
    removeFile("/var/log/jailbreakd-stdout.log");
    
    launch("/var/containers/Bundle/iosbinpack64/bin/launchctl", "unload", "/var/containers/Bundle/iosbinpack64/LaunchDaemons", NULL, NULL, NULL, NULL, NULL);
    launch("/var/containers/Bundle/iosbinpack64/bin/launchctl", "load", "/var/containers/Bundle/iosbinpack64/LaunchDaemons", NULL, NULL, NULL, NULL, NULL);
    
    sleep(1);
    
    failIf(!fileExists("/var/log/testbin.log"), "[-] Failed to load launch daemons");

    if (maxVersion("11.4.1")) {
        failIf(!fileExists("/var/log/jailbreakd-stdout.log"), "[-] Failed to load jailbreakd");

        // trust
        failIf(trustbin(in_bundle("dylibs/launchd_payload.dylib")), "[-] Failed to trust pspawn payload");
        
        // entitle it
        failIf(!setcsflags(1), "[-] Failed to entitle launchd");
        failIf(!entitlePidOnAMFI(1, "get-task-allow", true), "[-] Failed to entitle launchd");
        failIf(!entitlePidOnAMFI(1, "com.apple.private.skip-library-validation", true), "[-] Failed to entitle launchd");
    }
    
    if (self.enableTweaks.isOn) {
        // inject
        failIf(inject_dylib(1, in_bundle("dylibs/launchd_payload.dylib")), "[-] Failed to inject code into launchd!");
        
        // cache and we're done
        pid_t installd = pid_of_procName("installd");
        failIf(!installd, "[-] Can't find installd's pid");
        
        pid_t backboardd = pid_of_procName("backboardd");
        failIf(!backboardd, "[-] Can't find backboardd's pid");
        
        LOG("[+] Really jailbroken!");
        term_jelbrek();
        
        /*
           now maybe I need to do a proper userland reload
           but ldrestart takes way too much time
           and yalu's version panics my device
           let's just leave it be like this
         */

        
        // AppSync
        kill(installd, SIGKILL);
        
        if ([self.installiSuperSU isOn]) {
            LOG("[*] Installing iSuperSU");
            copyFile(in_bundle("apps/iSuperSU.app"), "/var/containers/Bundle/tweaksupport/Applications/iSuperSU.app");
            launch("/var/containers/Bundle/tweaksupport/usr/bin/uicache", NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        }
        
        // bye bye
        kill(backboardd, SIGKILL);
        exit(0);
    }
    
    if (maxVersion("11.4.1")) {
        pid_t installd = pid_of_procName("installd");
        failIf(!installd, "[-] Can't find installd's pid");
        
        failIf(!setcsflags(installd), "[-] Failed to entitle installd");
        failIf(!entitlePidOnAMFI(installd, "get-task-allow", true), "[-] Failed to entitle installd");
        failIf(!entitlePidOnAMFI(installd, "com.apple.private.skip-library-validation", true), "[-] Failed to entitle installd");
        
        inject_dylib(installd, "/var/containers/Bundle/tweaksupport/usr/lib/TweakInject/AppSyncUnified.dylib");
        
        if ([self.installiSuperSU isOn]) {
            LOG("[*] Installing iSuperSU");
            copyFile(in_bundle("apps/iSuperSU.app"), "/var/containers/Bundle/tweaksupport/Applications/iSuperSU.app");
            launch("/var/containers/Bundle/tweaksupport/usr/bin/uicache", NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        }
    }
    
    LOG("[+] Jailbreak succeeded. Enjoy");
    
end:;
    
    if (sb) sandbox(getpid(), sb);
    term_jelbrek();
}
- (IBAction)uninstall:(id)sender {
    //---- tfp0 ----//
    mach_port_t taskforpidzero = MACH_PORT_NULL;
    
    uint64_t sb = 0;
    BOOL debug = NO; // kids don't enable this
    
    NSError *error = NULL;
    
    if (debug) {
        kern_return_t ret = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &taskforpidzero);
        if (ret) {
            printf("[-] Error using hgsp! '%s'\n", mach_error_string(ret));
            printf("[*] Using exploit!\n");
            
            if (!maxVersion("11.4.1") && maxVersion("12.1.2")) {
                taskforpidzero = voucher_swap();
            }
            else if (maxVersion("11.3.1")) {
                taskforpidzero = exploit();
            }
            
            if (!MACH_PORT_VALID(taskforpidzero)) {
                LOG("[-] Exploit failed");
                LOG("[i] Please try again");
                sleep(1);
                return;
            }
        }
    }
    else {
        if (!maxVersion("11.4.1") && maxVersion("12.1.2")) {
            taskforpidzero = voucher_swap();
        }
        else if (maxVersion("11.3.1")) {
            taskforpidzero = exploit();
        }
        
        if (!MACH_PORT_VALID(taskforpidzero)) {
            LOG("[-] Exploit failed");
            LOG("[i] Please try again");
            sleep(1);
            return;
        }
    }
    LOG("[*] Starting fun");
    
    if (!maxVersion("11.4.1") && maxVersion("12.1.2")) {
        kernel_slide_init();
        init_with_kbase(taskforpidzero, 0xfffffff007004000 + kernel_slide);
    }
    else if (maxVersion("11.3.1")) {
        init_jelbrek(taskforpidzero);
    }
    
    LOG("[i] Kernel base: 0x%llx", KernelBase);
    
    //---- basics ----//
    rootify(getpid()); // give us root
    LOG("[i] uid: %d\n", getuid());
    failIf(getuid(), "[-] Failed to get root");
    
    sb = unsandbox(getpid()); // escape sandbox
    FILE *f = fopen("/var/mobile/.roottest", "w");
    failIf(!f, "[-] Failed to escape sandbox!");
    
    LOG("[+] Escaped sandbox!\n\tWrote file %p", f);
    fclose(f);
    removeFile("/var/mobile/.roottest");
    
    setcsflags(getpid()); // set some csflags
    platformize(getpid()); // set TF_PLATFORM
    
    if (debug) setHSP4();
    if (debug) PatchHostPriv(mach_host_self());
    
    LOG("[*] Uninstalling...");
    
    removeFile("/var/LIB");
    removeFile("/var/ulb");
    removeFile("/var/bin");
    removeFile("/var/sbin");
    removeFile("/var/containers/Bundle/tweaksupport/Applications");
    removeFile("/var/Apps");
    removeFile("/var/profile");
    removeFile("/var/motd");
    removeFile("/var/dropbear");
    removeFile("/var/containers/Bundle/tweaksupport");
    removeFile("/var/containers/Bundle/iosbinpack64");
    removeFile("/var/containers/Bundle/dylibs");
    removeFile("/var/log/testbin.log");
    removeFile("/var/log/jailbreakd-stdout.log");
    removeFile("/var/log/jailbreakd-stderr.log");
    
end:;
    if (sb) sandbox(getpid(), sb);
    term_jelbrek();
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
