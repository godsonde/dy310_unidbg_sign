package com.ss.android.ugc.aweme;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.arm.backend.*;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.SystemPropertyHook;
import com.github.unidbg.linux.android.SystemPropertyProvider;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.wrapper.DvmBoolean;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.Module;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.virtualmodule.android.AndroidModule;
import com.github.unidbg.virtualmodule.android.JniGraphics;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.HashMap;
import java.util.Map;
import com.google.gson.Gson;

public class Sign664 extends AbstractJni {
    public static class LibraryLoader {
        public static DalvikModule loadLibrary(AndroidEmulator emulator, VM vm, String resourcePath) throws IOException {
            // 从jar包资源中读取so文件
            try (InputStream is = LibraryLoader.class.getResourceAsStream(resourcePath)) {
                // 创建临时文件
                File tempFile = File.createTempFile("lib", ".so");
                tempFile.deleteOnExit(); // 程序退出时删除临时文件

                // 将资源文件复制到临时文件
                Files.copy(is, tempFile.toPath(), StandardCopyOption.REPLACE_EXISTING);

                // 加载so文件
                return vm.loadLibrary(tempFile, true);
            }catch (FileNotFoundException e) {
                // 资源文件未找到
                System.err.println("Library resource not found: " + resourcePath);
                throw e;
            } catch (IOException e) {
                // 文件操作异常
                System.err.println("Error loading library: " + resourcePath);
                throw e;
            }
        }
    }
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
    private final Memory memory;

    public Sign664() {
        emulator = AndroidEmulatorBuilder
                .for64Bit()
                .setProcessName("com.ss.android.ugc.aweme")
                //.addBackendFactory(new Unicorn2Factory(true))
                .build();
        //emulator.getBackend().registerEmuCountHook(100000);//100000
        emulator.getSyscallHandler().setVerbose(false);
        emulator.getSyscallHandler().setEnableThreadDispatcher(true);


        memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
//        memory.setLibraryResolver(new AndroidResolver(28));
        memory.setCallInitFunction(true);

//        vm = emulator.createDalvikVM(new File("unidbg-android/src/test/resources/dy233/dy233.apk"));
//        vm = emulator.createDalvikVM(new File("unidbg-android/src/test/resources/dy310/douyin31.0.apk"));
//        vm = emulator.createDalvikVM(new File("unidbg-android/src/test/resources/dy289/douy28.9.0.apk"));
        vm = emulator.createDalvikVM();
        vm.setJni(this);
        vm.setVerbose(false);

//        emulator.showRegs();
        new AndroidModule(emulator, vm).register(memory);
        new JniGraphics(emulator, vm).register(memory);
//        DvmClass a = vm.resolveClass("ms/bd/c/k");
        DvmClass a = vm.resolveClass("ms/bd/c/l");
//        DvmClass b = vm.resolveClass("ms/bd/c/a0", a);
        DvmClass b = vm.resolveClass("ms/bd/c/e0", a);
        DvmClass c = vm.resolveClass("com/bytedance/mobsec/metasec/ml/MS", b);

//        DalvikModule dm = vm.loadLibrary("metasec_ml", true);
        File file1 = new File("unidbg-android/src/test/resources/dy310/libmetasec_ml.so");
        File file2 = new File("libmetasec_ml.so");
        File fileToLoad = file1.exists() ? file1 : (file2.exists() ? file2 : null);
//        DalvikModule dm = vm.loadLibrary(new File("unidbg-android/src/test/resources/dy310/libmetasec_ml.so"), true);
        DalvikModule dm1 = null;
        DalvikModule dm2 = null;
        if(fileToLoad != null)
            dm1 = vm.loadLibrary(fileToLoad, true);
        try {
            dm2 = LibraryLoader.loadLibrary(emulator, vm, "/dy310/libmetasec_ml.so");
            // 后续操作
        } catch (IOException e) {
            // 处理加载so文件失败的情况
            System.err.println("Failed to load library: " + e.getMessage());
            // 可以选择抛出异常或者采取其他恢复策略
            throw new RuntimeException("Library load failed", e);
        }
        //DalvikModule dm2 = LibraryLoader.loadLibrary(emulator, vm, "/dy310/libmetasec_ml.so");
        DalvikModule dm = dm1!=null?dm1:dm2;
        module = dm.getModule();
//        System.out.println("libmetasec_ml base:"+module.base+" size:"+module.size+" ");

        dm.callJNI_OnLoad(emulator);
//        System.out.println("ok");
        String classPath = System.getProperty("java.class.path");
//        System.out.println("Class Path: " + classPath);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
//        System.out.println("callObjectMethodV "+ signature);
        switch (signature) {
            case "java/lang/Thread->getStackTrace()[Ljava/lang/StackTraceElement;": {
                DvmObject<?>[] a = {
                        vm.resolveClass("java/lang/StackTraceElement").newObject("dalvik.system.VMStack"),
                        vm.resolveClass("java/lang/StackTraceElement").newObject("java.lang.Thread")
                };
                return new ArrayObject(a);
            }
        }
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
//        System.out.println("callStaticObjectMethodV "+ signature);
        switch (signature) {
            case "com/bytedance/mobsec/metasec/ml/MS->b(IIJLjava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;": {
                int a = vaList.getIntArg(0);
//                System.out.println("----------------------------");
//                System.out.println("callStaticObjectMethodV "+a);
//                System.out.println("----------------------------");
                if (a == 65539) {
                    return new StringObject(vm,"/data/user/0/com.ss.android.ugc.aweme/files/;o@Y0f");
//                    return new StringObject(vm,"/data/user/0/com.ss.android.ugc.aweme/files/.msdata");
                } else if (a == 33554433) {
                    return DvmBoolean.valueOf(vm, Boolean.TRUE);
                } else if (a == 33554434) {
                    return DvmBoolean.valueOf(vm, Boolean.TRUE);
                } else if (a == 16777233) {
//                    return new StringObject(vm, "23.3.0");
//                    return new StringObject(vm, "28.9.0");
                    return new StringObject(vm, "31.0.0");
                }
            }
            case "java/lang/Thread->currentThread()Ljava/lang/Thread;": {
                return vm.resolveClass("java/lang/Thread").newObject(Thread.currentThread());
            }
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public void callStaticVoidMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
//        System.out.println("callStaticVoidMethodV "+ signature);
        switch (signature) {
            case "com/bytedance/mobsec/metasec/ml/MS->a()V": {
                return;
            }
        }
        super.callStaticVoidMethodV(vm, dvmClass, signature, vaList);
    }

    public String GetSign(String url, String header) {
        try {
//            Number number = module.callFunction(emulator,
//                    0x438c0+1, url, header // 23.4
//            );
            Number number = module.callFunction(emulator,
                    0xf4b60, url, header // 31.0
            );
//            Number number = module.callFunction(emulator,
//                    0x6fc20+1, url, header
//            );
//            Number number = module.callFunction(emulator,
//                    0xbe040+1, url, header // 28.9
//            );
//            System.out.printf("0X%X\n", number.intValue());
            int hash = number.intValue();
            if (this.vm.getObject(hash) == null) {
//                System.out.printf("0X%X is null\n", number.intValue());
            }
            UnidbgPointer p = memory.pointer(hash & 0xffffffffL);
            return p.getString(0);
        } catch (BackendException e) {
            System.err.println("Memory access error: " + e.getMessage());
        }

        return "";
    }

    public static void main(String[] args) {


        //String s1 = "https://api5-normal-lf.amemv.com/aweme/v1/user/follower/list/banner/?user_id=3830306185163203&sec_user_id=MS4wLjABAAAAIRSCtI5d0UQ_-6rmNfxsLkBMRi0dBwHWX_KJZzeXbgRlRoATUfQGokdlFlic16PV&max_time=0&count=20&offset=0&source_type=2&address_book_access=2&gps_access=1&vcd_count=0&store_page=null&klink_egdi=AAKkg85-bL7cFN_FFk8JUNjICTVWmYPGbIkaSXx0pAVKiR-L4eiIBwMZ&_rticket=1736131570726&first_launch_timestamp=0&last_deeplink_update_version_code=0&is_preinstall=0&need_personal_recommend=1&is_android_fold=0&ts=1736131567&ac=wifi&aid=1128&appTheme=light&app_name=aweme&app_type=normal&cdid=7ba309c0-9a01-4861-bfce-5be7010779f7&channel=huawei_1128_64&cpu_support64=true&device_brand=google&device_id=4325905435466956&device_platform=android&device_type=Pixel+3&dpi=440&host_abi=arm64-v8a&iid=2601889902139211&is_android_pad=0&is_guest_mode=0&language=zh&manifest_version_code=310001&minor_status=0&os=android&os_api=28&os_version=9&resolution=1080*2028&ssmix=a&update_version_code=31009900&version_code=310000&version_name=31.0.0";
        String s1 = "https://api5-normal-lf.amemv.com/aweme/v1/user/follower/list/?user_id=2663467208150212&sec_user_id=MS4wLjABAAAA5FKxdHznY9HEw8zLew6_n93cIsGENqLLDZwuwryzxoz2EhpUZasoMET_yCxfoJbW&max_time=0&count=20&offset=0&source_type=2&address_book_access=2&gps_access=1&vcd_count=0&store_page=null&klink_egdi=AAKkg85-bL7cFN_FFk8JUNjICTVWmYPGbIkaSXx0pAVKiR-L4eiIBwMZ&_rticket=1736131570726&first_launch_timestamp=0&last_deeplink_update_version_code=0&is_preinstall=0&need_personal_recommend=1&is_android_fold=0&ts=1736761384&is_guest_mode=0&manifest_version_code=310001&_rticket=1736761388307&app_type=normal&is_preinstall=0&iid=2601889902139211&channel=huawei_1128_64&is_android_pad=0&ping-interval=30&device_type=Pixel%203&language=zh&cpu_support64=true&host_abi=arm64-v8a&resolution=1080*2028&openudid=54a7de9d2c50e422&update_version_code=31009900&cdid=7ba309c0-9a01-4861-bfce-5be7010779f7&minor_status=0&appTheme=light&os_api=28&qos_level=2&klink_egdi=AAKkg85-bL7cFN_FFk8JUNjICTVWmYPGbIkaSXx0pAVKiR-L4eiIBwMZ&is_android_fold=0&dpi=440&ac=wifi&is_background=0&device_id=4325905435466956&os=android&os_version=9&version_code=310000&last_deeplink_update_version_code=0&ttnet_heartbeat_interval=30&app_name=aweme&version_name=31.0.0&device_brand=google&need_personal_recommend=1&ne=1&device_platform=android&first_launch_timestamp=0&ws_connect_protocol=0&aid=1128&ttnet_ignore_offline=1&ts=1736128835";
//        String s2 = "cookie\r\n"+
//                "is_staff_user=false; store-region=cn-ln; store-region-src=uid; ticket_guard_has_set_public_key=1; passport_csrf_token=55148555904f419485a9e3c845143b59; passport_csrf_token_default=55148555904f419485a9e3c845143b59; install_id=2601889902139211; ttreq=1$5c00ff16f56fffca013112059790c761f4d58496; d_ticket=009ce0e9c1c861a523cc914778203c3311f87; multi_sids=2450150556175815%3A09766122bfe8f692ad2cc0e9f90756e9%7C3830306185163203%3A3a2879e1407e868681c557b152d01d5b; sid_tt=09766122bfe8f692ad2cc0e9f90756e9; sessionid=09766122bfe8f692ad2cc0e9f90756e9; sessionid_ss=09766122bfe8f692ad2cc0e9f90756e9; passport_mfa_token=CjaUxyd1aSst34nnimJOVANFGSFdbetEx%2F%2B%2F2EPiH6wcj%2BwciSV5tsIKtPKBqrdphn6Ae%2FHZAXoaSgo8RT4OY7AaqS5efhQ1Q%2BaRMmw93NzMLcZZae1QAxaD6UrP1wjXbREfQy4J3n3BUdqXsD2sGN2yPXkZWAEJENCI5g0Y9rHRbCACIgEDgAgY9Q%3D%3D; passport_assist_user=CkEDz3mfHrrVRfsUN9_VOefA9sntCW_64wVwOlkibaNVmyAZPD5hxMWek7eh61jG_lSBjmnMmSejXEyawbVQUs3YnxpKCjyFmh4igFZztdCzjLzb-JUU6N9iKFMecmM3dvJeR6hQG1Bf9rx-JO5Jc0S42VQIfL4Ix81L58Lf1Szjw9EQ6IjmDRiJr9ZUIAEiAQOGw1-f; n_mh=N6GLQKPZH2NkSocJzhGsWTO6uESrbaCDbi66rTTgjjk; sid_guard=09766122bfe8f692ad2cc0e9f90756e9%7C1736131526%7C5184000%7CFri%2C+07-Mar-2025+02%3A45%3A26+GMT; uid_tt=7402f965a18dc28410b459c95e264075; uid_tt_ss=7402f965a18dc28410b459c95e264075; odin_tt=c77b7c89d7e13feeeb2c187f1e1ef39cc44387eb7619ef09747f62319ca7931cc394ce7856aca0e34863a01c417dc880cf7eebd3a92c5a6f40361628fa474b3326f9c9537a7ee45ab967a9479a18c8d2\r\n"+
//                "x-tt-dt\r\n"+
//                "AAAX6XAFMEMY4QDQNTUXOFQDY5FEBECXUSABH7Z2POQUZGAA4EDIGBU674RXD6OXN6UKV3E6ZXWGDL2WWLUKSM4ZABKLVGGQLPT25KFXTBOIUVNHI37LSAN5IZX2WPCWMDHNLVCWRA6EJBLNWOJBJLY\r\n"+
//                "activity_now_client\r\n"+
//                "1735032011458\r\n"+
//                "x-ss-req-ticket\r\n"+
//                "1735032009354\r\n"+
//                "x-bd-client-key\r\n"+
//                "c9fd4ea1e3e21e57a792371ef11f574d3a38be49b1579cbcdf685fda4fd669d184609486196db2930052c33d23c14e2f7ff21463cb983c77898fe100b34a3cd8\r\n"+

        String s2 = "x-bd-kmsv\r\n"+
                "1\r\n"+
                "sdk-version\r\n"+
                "2\r\n"+
                "x-tt-token\r\n"+
                "00620223addceb4d621e61a84d99b3ceb001403ba4a5ec685aca7a170c2d2b940d80e55e61323b8013b9ecf634de32a43c17f419a4a30dbe9b98b165f44c425e29f45149e9aed7d9a14be20fbea57d7a07c2718aaabe0052136294bc9021b1eaeb872-1.0.1\r\n"+
                "passport-sdk-version\r\n"+
                "203240\r\n"+
                "x-vc-bdturing-sdk-version\r\n"+
                "3.7.2.cn\r\n"+
                "x-tt-store-region\r\n"+
                "cn-ln\r\n"+
                "x-tt-store-region-src\r\n"+
                "uid\r\n"+
                "x-tt-request-tag\r\n"+
                "s=1;p=0\r\n"+
                "x-ss-dp\r\n"+
                "1128\r\n"+
//                "x-tt-trace-id\r\n"+
//                "00-f7f774210df5e6358d01cccc326a0468-f7f774210df5e635-01\r\n"+
                "User-Agent\r\n"+
                "com.ss.android.ugc.aweme/310001 (Linux; U; Android 9; zh_CN_#Hans; Pixel 3; Build/PQ3A.190801.002; Cronet/TTNetVersion:df97b55e 2024-07-17 QuicVersion:182d68c8 2024-05-28)\r\n"+
                "accept-encoding\r\n"+
                "gzip, deflate, br";
//        System.out.println("url: " + s1);
//        System.out.println("head: " + s2);
        if (args.length > 1)
        {
            // 获取两个字符串参数
            s1 = args[0];
            s2 = args[1];

            // 使用这两个参数
            System.out.println("第一个参数: " + s1);
            System.out.println("第二个参数: " + s2);
        }

        Sign664 sign6 = new Sign664();
        String sign = sign6.GetSign(s1, s2);
        System.out.println(sign);
        try {
            FileWriter writer = new FileWriter("outputold.txt");
            writer.write(sign);
            writer.close();
            System.out.println("文件写入成功");
        } catch (IOException e) {
            e.printStackTrace();
        }
        // 创建Map存储结果
        Map<String, String> resultMap = new HashMap<>();

        // 按行分割
        String[] lines = sign.split("\r\n");

        // 遍历处理每一行
        for (int i = 0; i < lines.length - 1; i += 2) {
            String key = lines[i].trim();
            String value = lines[i + 1].trim();
            resultMap.put(key, value);
        }
        Gson gson = new Gson();
        String json = gson.toJson(resultMap);
        try {
            FileWriter writer = new FileWriter("output.txt");
            writer.write(json);
            writer.close();
            System.out.println("文件写入成功");
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
