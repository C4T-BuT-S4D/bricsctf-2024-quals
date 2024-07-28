import java.util.Scanner;
import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public class Dolly {
    // VARIABLES

    static {
        try {
            var filename = "libchecker.so";
            var directory = Path.of("/tmp/dolly-" + System.currentTimeMillis());

            Files.createDirectory(directory);

            var file = Files.createFile(
                Path.of(directory.toString(), filename)
            );

            file.toFile().deleteOnExit();
            directory.toFile().deleteOnExit();

            var stream = new FileOutputStream(file.toFile());
            var bufferedStream = new BufferedOutputStream(stream, 0x200000);

            // WRITES

            bufferedStream.close();
            stream.close();

            System.load(file.toString());

            Files.delete(file);
            Files.delete(directory);
        } catch (Exception ignored) { }
    }

    private static native boolean checkFlag(String flag);

    private static byte[] decryptData(byte[] data) {
        var result = new byte[data.length];
        
        var tmp = (byte)0xFF;
    
        for (var i = 0; i < data.length; i += 1) {
            var value = data[i];

            value = (byte)((value ^ tmp) & 0xFF);
            value = (byte)((value ^ (i)) & 0xFF);
            value = (byte)((value + (i*i)) & 0xFF);
            value = (byte)((value ^ (i*i*i)) & 0xFF);
            value = (byte)((value + (i*i*i*i)) & 0xFF);

            result[i] = value;
            
            tmp = (byte)((tmp + value) & 0xFF);
        }
    
        return result;
    }

    private static boolean isPrintable(String s) {
        for (var i = 0; i < s.length(); i += 1) {
            var c = s.charAt(i);

            if (c < 0x20 || c > 0x7e) {
                return false;
            }
        }

        return true;
    }

    public static void run() {
        System.out.print("[*] Please enter the flag:\n");
        System.out.print("> ");

        var scanner = new Scanner(System.in);
        var flag = scanner.hasNextLine() ? scanner.nextLine() : "";
        scanner.close();

        if (isPrintable(flag) && checkFlag(flag)) {
            System.out.print("[+] Correct flag!\n");
        } else {
            System.out.print("[-] Wrong flag :(\n");
        }

        return;
    }
}
