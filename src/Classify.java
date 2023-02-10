import java.io.*;
import java.util.ArrayList;

public class Classify {
    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_BLACK = "\u001B[30m";
    public static final String ANSI_RED = "\u001B[31m";
    public static final String ANSI_GREEN = "\u001B[32m";
    public static final String ANSI_YELLOW = "\u001B[33m";
    public static final String ANSI_BLUE = "\u001B[34m";
    public static final String ANSI_PURPLE = "\u001B[35m";
    public static final String ANSI_CYAN = "\u001B[36m";
    public static final String ANSI_WHITE = "\u001B[37m";

    public void train(String weka_path, int classifier, String work_folder, int cross_validation, boolean ga_on) {
        if (ga_on)
            System.out.println(ANSI_BLUE + "Results using GA:" + ANSI_RESET); // With GA performance
        else
            System.out.println(ANSI_BLUE + "Results without using GA:" + ANSI_RESET); // Without GA performance

        // Train and test the truncated training file
        try {
            Process p = null;

            if (ga_on)
                p = Runtime.getRuntime().exec("java -cp " + weka_path + " " + classifier + " -t " + work_folder + "/examples_selected.arff -d " + work_folder + "/weka_model_ga -x " + cross_validation);
            else
                p = Runtime.getRuntime().exec("java -cp " + weka_path + " " + classifier + " -t " + work_folder+ "/examples.arff -d " + work_folder + "/weka_model_all -x " + cross_validation);

            BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));
            BufferedReader stdError = new BufferedReader(new InputStreamReader(p.getErrorStream()));

            // read the output from the command
            String s = null;
            while ((s = stdInput.readLine()) != null)
                System.out.println(s);
            stdInput.close();

            // read any errors from the attempted command
            while ((s = stdError.readLine()) != null)
                System.out.println(s);
            stdError.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////
    // For testing all the packets in a pcap file (rather than going n packets at a time) //
    ////////////////////////////////////////////////////////////////////////////////////////
    public void classify_test_all(String weka_path, String classifier, String work_folder, int cross_validation, int no_of_packets_per_group, String os, boolean ga_on) {
        if (ga_on) // With GA performance
            System.out.println(ANSI_BLUE + "Results using GA:" + ANSI_RESET);
        else // Without GA performance
            System.out.println(ANSI_BLUE + "Results without using GA:" + ANSI_RESET);

        //////////////////////////////////////
        // Test the truncated training file //
        //////////////////////////////////////
        try {
            Process p = null;

            if (ga_on)
                p = Runtime.getRuntime().exec("java -cp " + weka_path + " " + classifier + " -T " + work_folder + "/examples_" + os + "_ga" + ".arff" + " -l " + work_folder + "/weka_model_ga");
            else
                p = Runtime.getRuntime().exec("java -cp " + weka_path + " " + classifier + " -T " + work_folder + "/examples_" + os + ".arff" + " -l " + work_folder + "/weka_model_all");

            BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));
            BufferedReader stdError = new BufferedReader(new InputStreamReader(p.getErrorStream()));

            String s = null;

            // read the output from the command
            while ((s = stdInput.readLine()) != null)
                System.out.println(s);
            stdInput.close();

            // read any errors from the attempted command
            while ((s = stdError.readLine()) != null)
                System.out.println(s);
            stdError.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //////////////////////////////////////////////////////
    // For testing packets in a pcap file one at a time //
    //////////////////////////////////////////////////////
    public void classify_test_one_by_one(String weka_path, String classifier, String work_folder, int cross_validation, int no_of_packets_per_group, String os, boolean ga_on) {
        ArrayList<String> arff_headers = new ArrayList<>();
        Process p = null;
        BufferedReader reader;
        int correctly_classified = 0;
        int incorrectly_classified = 0;

        // Get parameters
        String read_file_path = null;
        String weka_read_path = null;
        String arff_read_path = null;
        if (ga_on) {
            read_file_path = work_folder + "/examples_" + os + "_ga";
            weka_read_path = "/weka_model_ga";
            arff_read_path = "/examples_selected.arff";
        }
        else {
            read_file_path = work_folder + "/examples_" + os;
            weka_read_path = "/weka_model_all";
            arff_read_path = "/examples.arff";
        }

        ///////////////////////
        // Read arff headers //
        ///////////////////////
        try {
            reader = new BufferedReader(new FileReader(work_folder + arff_read_path));

            String line;
            while ((line = reader.readLine()) != null) {
                if (line.trim().isEmpty())
                    arff_headers.add(line);
                else if (line.substring(0, 1).equals("@"))
                    arff_headers.add(line);
                else
                    break;
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        ////////////////////////////////
        // For each example, classify //
        ////////////////////////////////
        int pos = 0;
        int current_no_of_examples = 0;

        int total_no_of_examples = get_no_of_lines(read_file_path);
        try {
            reader = new BufferedReader(new FileReader(read_file_path));

            String line;
            ArrayList<Results> results = new ArrayList<>();
            while ((line = reader.readLine()) != null) {
                if (!line.trim().isEmpty()) {
                    pos++;
                    current_no_of_examples++;

                    System.out.print("Classifying example: " + current_no_of_examples + "/" + total_no_of_examples + "\r");

                    // Convert the example to arff file
                    try {
                        File file = new File(read_file_path + "_" + no_of_packets_per_group + "_single.arff");
                        BufferedWriter output_text = new BufferedWriter(new FileWriter(file, false));

                        // Write the headers
                        for (int k = 0; k < arff_headers.size(); k++) {
                            output_text.write(arff_headers.get(k));
                            output_text.newLine();
                            output_text.flush();
                        }

                        // Write the examples
                        output_text.write(line);
                        output_text.flush();
                        output_text.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                    // Test the file
                    try {
                        p = Runtime.getRuntime().exec("java -cp " + weka_path + " " + classifier + " -T " + read_file_path + "_" + no_of_packets_per_group + "_single.arff -l " + work_folder + weka_read_path);

                        BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));
                        BufferedReader stdError = new BufferedReader(new InputStreamReader(p.getErrorStream()));

                        // read the output from the command
                        String s = null;
                        // skip lines until the results start
                        while (!((s = stdInput.readLine()).contains("classified as"))) {}

                        ArrayList<String> classes = new ArrayList<>();
                        int pos_of_class = 0;
                        while ((s = stdInput.readLine()) != null) {
                            s = s.trim();

                            String line2[] = s.split(" ");
                            classes.add(line2[line2.length - 1]);

                            if (s.split("=")[0].contains("1")) {
                                for (int k = 0; k < line2.length; k++) {
                                    if (line2[k].equals("1")) {
                                        pos_of_class = k;
                                        break;
                                    }
                                }
                            }
                        }

                        add(results, classes.get(pos_of_class));

                        // read any errors from the attempted command
                        while ((s = stdError.readLine()) != null)
                            System.out.println(s);

                        stdInput.close();
                        stdError.close();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                    if ((pos == no_of_packets_per_group) || (current_no_of_examples == total_no_of_examples)) {
                        if (results.get(0).class_os.equals(os))
                            correctly_classified++;
                        else
                            incorrectly_classified++;

                        pos = 0;
                        results = new ArrayList<>(); // clear
                    }
                }
            }

            double result = correctly_classified / (double)(correctly_classified + incorrectly_classified);
            System.out.println();
            System.out.println("Performance: " + result);
            System.out.println("No. of groups: " + (correctly_classified + incorrectly_classified));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    void add(ArrayList<Results> array, String os) {
        // if array empty
        if (array.size() == 0) {
            Results temp = new Results();
            temp.occurence++;
            temp.class_os = os;
            array.add(temp);
        }
        else {
            boolean exists = false;
            int pos = 0;
            // check if it exists
            for (int i = 0; i < array.size(); i++) {
                if (array.get(i).class_os.equals(os)) {
                    pos = i;
                    exists = true;
                    break;
                }
            }

            // if it exists
            if (exists) {
                // increase occurence
                Results temp = new Results();
                temp.occurence = array.get(pos).occurence;
                temp.occurence++;
                temp.class_os = os;
                array.set(pos, temp);

                // sort
                for (int i = pos; i > 0; i--) {
                    if (array.get(i).occurence > array.get(i-1).occurence) {
                        // swap
                        Results temp2 = array.get(i);
                        array.set(i, array.get(i-1));
                        array.set(i-1, temp2);
                    }
                    else
                        break;
                }
            }
            else {
                Results temp = new Results();
                temp.occurence++;
                temp.class_os = os;
                array.add(temp);
            }
        }
    }

    public void remove_arff_headers(String input_filename, String output_filename) {
        try {
            BufferedReader in = new BufferedReader(new FileReader(input_filename));
            PrintWriter out = new PrintWriter (output_filename);

            boolean start_writing = false;
            for (String line; (line = in.readLine()) != null;) {
                if (line.equals("@data")) {
                    start_writing = true;
                    line = in.readLine();
                }

                if ((start_writing) && (!line.trim().isEmpty()))
                    out.println(line);
            }

            in.close();
            out.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        };
    }

    ///////////////////////////////////////////
    // Returns the number of lines in a file //
    ///////////////////////////////////////////
    public static int get_no_of_lines(String filename) {
        int no_of_lines = 0;
        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader(filename));

            String line;
            while ((line = reader.readLine()) != null)
                if (!line.trim().isEmpty())
                    no_of_lines++;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return no_of_lines;
    }

    class Results {
        int occurence = 0;
        String class_os = "";
    }
}

