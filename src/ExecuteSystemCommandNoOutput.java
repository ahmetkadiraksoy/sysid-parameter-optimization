public class ExecuteSystemCommandNoOutput {
    public void execute(String cmdLine) {
        try {
            Process p = Runtime.getRuntime().exec(cmdLine);
            p.waitFor();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}