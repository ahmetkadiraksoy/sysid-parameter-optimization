import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;

public class ExecuteSystemCommand {
    public ArrayList<String> execute(String cmdLine, boolean parse) {
        ArrayList<String> output = new ArrayList<>();
        String line;
        try {
            Process p = Runtime.getRuntime().exec(cmdLine);
            BufferedReader input = new BufferedReader(new InputStreamReader(p.getInputStream()));
            while ((line = input.readLine()) != null) {
                if (!parse)
                    output.add(line);
                else {
                    if (line.trim().length() == 0)
                        output.add("?");
                    else {
                        if (line.contains(","))
                            line = line.split(",")[0];

                        if (line.contains("0x"))
                            line = line.split("x")[1];

                        output.add(line);
                    }
                }
            }

            input.close();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return output;
    }
}