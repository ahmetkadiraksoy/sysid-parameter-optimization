import weka.classifiers.Classifier;
import weka.classifiers.bayes.BayesNet;
import weka.classifiers.functions.LinearRegression;
import weka.classifiers.functions.Logistic;
import weka.classifiers.functions.MultilayerPerceptron;
import weka.classifiers.functions.SMO;
import weka.classifiers.rules.*;
import weka.classifiers.trees.DecisionStump;
import weka.classifiers.trees.J48;
import weka.classifiers.trees.RandomForest;
import weka.core.Instances;
import weka.core.converters.ArffSaver;
import weka.core.converters.CSVLoader;

import java.io.*;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

public class Main {
    private static final String ANSI_RESET = "\u001B[0m";
    private static final String ANSI_RED = "\u001B[31m";
    private static final String ANSI_GREEN = "\u001B[32m";
    private static final String ANSI_BLUE = "\u001B[34m";
    private static final String ANSI_BLACK = "\u001B[30m";
    private static final String ANSI_YELLOW = "\u001B[33m";
    private static final String ANSI_PURPLE = "\u001B[35m";
    private static final String ANSI_CYAN = "\u001B[36m";
    private static final String ANSI_WHITE = "\u001B[37m";

    public static void main (String args[]) {
        // Parameters
        String work_folder = "./"; // default folder for workspace
        String config_path = ""; // path to config file
        String selected_features_file_path;
        String weka_path = "./weka.jar"; // default path to the weka jar file
        int classifier = 0; // default classifier (J48)
        String protocol = null; // name of the TCP/IP protocol to be processed
        String protocolToFilter = null; // name of the TCP/IP protocol to be selected among packets
        String class_os = ""; // OS(es) to be used for performing testing
        String weights = "0.95,0.05";
        String work_folder_pcap_files_train;
        String work_folder_pcap_files_test;
        String tshark_features_list_path;
        String tsharkselected_features_list_path;
        String features_path;
        ArrayList<String> pcapnames_train; // path to the file containing the OS names (classes)
        ArrayList<String> pcapnames_test; // path to the file containing the OS names (classes)
        ArrayList<String> classes;
        int mode = 0; // mode
        int iteration = 10; // number of iterations to be performed by GA
        int population_ga = 50;
        int max_threads = Runtime.getRuntime().availableProcessors() - 1;
        int no_of_os_instances_train;
        int no_of_os_instances_test;
        int group = 1;
        String k = "";
        int run_no = 0;
        int tournamentSize = 5;
        boolean verbose = false;
        boolean useDerivedFeatures = false;
        boolean useStreamFeatures = false;
        boolean optimizeParameters = true;
        double threshold_group = 0;
        double uniformRate = 0.5;
        double mutationRate = 0.05;

        // Use a set of classifiers
        Classifier[] models = {
                new J48(), // a decision tree (0)
                new PART(), // (1)
                new DecisionTable(), // decision table majority classifier (2)
                new DecisionStump(), // one-level decision tree (3)
                new ZeroR(), // (4)
                new OneR(), // one-rule classifier (5)
                new MultilayerPerceptron(), // neural network (6)
                new RandomForest(), // (7)
                new SMO(), // (8)
                new JRip(), // (9)
                new Logistic(), // (10)
                new LinearRegression(), // (11)
                new BayesNet() // (12)
        };

        // protocols whose accuracies we tested
        ArrayList<String> known_protocols = new ArrayList<>();
        known_protocols.add("ip");
        known_protocols.add("tcp");
        known_protocols.add("udp");
        known_protocols.add("dns");
        known_protocols.add("http");
        known_protocols.add("icmp");
        known_protocols.add("ssl");

        // analysis suffix
        ArrayList<String> derivedFeaturesSuffixConsider = new ArrayList<>();
        derivedFeaturesSuffixConsider.add("min");
        derivedFeaturesSuffixConsider.add("median");
        derivedFeaturesSuffixConsider.add("mean");
        derivedFeaturesSuffixConsider.add("max");
        derivedFeaturesSuffixConsider.add("mostcommon");
        derivedFeaturesSuffixConsider.add("variance");
        derivedFeaturesSuffixConsider.add("interquartile");
        derivedFeaturesSuffixConsider.add("stddeviation");
        derivedFeaturesSuffixConsider.add("uniquecount");

        // features that are not to be re-generated to contain analysis features (min, max)
        ArrayList<String> derivedFeaturesSuffixIgnore = new ArrayList<>();
        derivedFeaturesSuffixIgnore.add("stream_dst_no");
        derivedFeaturesSuffixIgnore.add("stream_dst_cantor");

        // features that are to be re-generated to contain analysis features (min, max) but not themselved
        ArrayList<String> derivedFeaturesSuffixInclude = new ArrayList<>();
        derivedFeaturesSuffixInclude.add("stream_synfin");
        derivedFeaturesSuffixInclude.add("stream_iat");
        derivedFeaturesSuffixInclude.add("stream_synfintime");
        derivedFeaturesSuffixInclude.add("stream_packetlength");

        //////////////////////////////////
        // Get attributes from the user //
        //////////////////////////////////
        if (args.length == 0) {
            help();
            System.exit(0);
        }

        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-w") || args[i].equals("--workfolder")) {
                work_folder = args[i+1];
                i++;
            }
            else if (args[i].equals("-we") || args[i].equals("--weights")) {
                weights = args[i+1];
                i++;
            }
            else if (args[i].equals("-p") || args[i].equals("--protocol")) {
                protocol = args[i+1];
                i++;
            }
            else if (args[i].equals("-pp") || args[i].equals("--packet-protocol")) {
                protocolToFilter = args[i+1];
                i++;
            }
            else if (args[i].equals("-r") || args[i].equals("--run")) {
                run_no = Integer.parseInt(args[i+1]);
                i++;
            }
            else if (args[i].equals("-pop") || args[i].equals("--population")) {
                population_ga = Integer.parseInt(args[i+1]);
                i++;
            }
            else if (args[i].equals("-m") || args[i].equals("--mode")) {
                mode = Integer.parseInt(args[i+1]);
                i++;
            }
            else if (args[i].equals("-tg") || args[i].equals("--threshold-group")) {
                threshold_group = Double.parseDouble(args[i+1]);
                i++;
            }
            else if (args[i].equals("-c") || args[i].equals("--classifier")) {
                classifier = Integer.parseInt(args[i+1]);
                i++;
            }
            else if (args[i].equals("-co") || args[i].equals("--config")) {
                config_path = args[i+1];
                i++;
            }
            else if (args[i].equals("-h") || args[i].equals("--help")) {
                help();
                System.exit(0);
            }
            else if (args[i].equals("-vb") || args[i].equals("--verbose")) {
                verbose = true;
            }
            else if (args[i].equals("-npo") || args[i].equals("--no-parameter-optimziation")) {
                optimizeParameters = false;
            }
            else if (args[i].equals("-k") || args[i].equals("--k")) {
                k = args[i+1];
                i++;
            }
            else if (args[i].equals("-i") || args[i].equals("--iteration")) {
                iteration = Integer.parseInt(args[i+1]);
                i++;
            }
            else if (args[i].equals("-t") || args[i].equals("--threads")) {
                max_threads = Integer.parseInt(args[i+1]);
                i++;
            }
            else if (args[i].equals("-g") || args[i].equals("--group")) {
                group = Integer.parseInt(args[i+1]);
                i++;
            }
            else if (args[i].equals("-os") || args[i].equals("--os-name")) {
                class_os = args[i+1];
                i++;
            }
            else if (args[i].equals("-wp") || args[i].equals("--weka-path")) {
                weka_path = args[i+1];
                i++;
            }
            else {
                System.out.println(ANSI_RED + "Unknown parameter '" + args[i] + "' " + ANSI_GREEN + "Type -h to see the help menu." + ANSI_RESET);
                System.exit(0);
            }
        }

        work_folder_pcap_files_train = work_folder + "/pcap_files/";
        work_folder_pcap_files_test = work_folder + "/pcap_files_test/";
        tshark_features_list_path =  work_folder + "/Tshark/" + protocol;
        tsharkselected_features_list_path = work_folder + "/TsharkSelected/" + protocol;
        features_path = work_folder + "/features/" + protocol;
        selected_features_file_path = work_folder + "/features/" + protocol + "/selected_feature_nos_by_ga_alg_" + classifier;
        if (run_no > 0)
            selected_features_file_path = selected_features_file_path + "_" + run_no;

        ///////////////////////////////////
        // Get the classes from the file //
        ///////////////////////////////////
        pcapnames_train = get_files_in_folder(work_folder_pcap_files_train);
        pcapnames_test = get_files_in_folder(work_folder_pcap_files_test);
        classes = get_number_of_OSes(work_folder_pcap_files_train);
        no_of_os_instances_train = pcapnames_train.size() / classes.size();
        no_of_os_instances_test = pcapnames_test.size() / classes.size();

        // Set class_os to 'all' if it is not provided
        if (class_os.equals(""))
            class_os = "all";

        GAParameters gaParameters = new GAParameters();
        gaParameters.weights = weights;
        gaParameters.classifier = classifier;
        gaParameters.iteration = iteration;
        if (new File(tsharkselected_features_list_path).exists())
            gaParameters.no_of_features = get_no_of_lines(tsharkselected_features_list_path);
        gaParameters.no_of_os_instances = no_of_os_instances_train;
        gaParameters.work_folder = features_path;
        gaParameters.max_threads = max_threads;
        gaParameters.tournamentSize = tournamentSize;
        gaParameters.uniformRate = uniformRate;
        gaParameters.mutationRate = mutationRate;
        gaParameters.preCalculatedGenes = new ArrayList<>();

        if (optimizeParameters) {
            if (classifier == 0)
                gaParameters.number_of_bits_for_parameters = 17;
            else if (classifier == 1)
                gaParameters.number_of_bits_for_parameters = 13;
            else if (classifier == 2)
                gaParameters.number_of_bits_for_parameters = 6;
            else if (classifier == 3)
                gaParameters.number_of_bits_for_parameters = 1;
            else if (classifier == 5)
                gaParameters.number_of_bits_for_parameters = 4;
            else if (classifier == 6)
                gaParameters.number_of_bits_for_parameters = 21;
            else if (classifier == 7)
                gaParameters.number_of_bits_for_parameters = 23;
            else if (classifier == 8)
                gaParameters.number_of_bits_for_parameters = 17;
            else if (classifier == 9)
                gaParameters.number_of_bits_for_parameters = 14;
            else if (classifier == 10)
                gaParameters.number_of_bits_for_parameters = 10;
            else if (classifier == 12)
                gaParameters.number_of_bits_for_parameters = 2;
        }
        else {
            gaParameters.number_of_bits_for_parameters = 0;
        }

        // Execute a mode
        switch (mode) {
            case 1:
                // Find non-null features
                findNonNullFeatures(protocolToFilter,
                        tshark_features_list_path,
                        tsharkselected_features_list_path,
                        pcapnames_train,
                        work_folder,
                        max_threads,
                        useDerivedFeatures,
                        useStreamFeatures,
                        derivedFeaturesSuffixConsider,
                        derivedFeaturesSuffixIgnore,
                        derivedFeaturesSuffixInclude);
                break;
            case 2:
                // Extract features for training
                extractFeatures(protocolToFilter,
                        pcapnames_train,
                        classes,
                        no_of_os_instances_train,
                        work_folder,
                        protocol,
                        useDerivedFeatures,
                        derivedFeaturesSuffixConsider,
                        derivedFeaturesSuffixIgnore,
                        derivedFeaturesSuffixInclude,
                        "pcap_files",
                        "train");
                break;
            case 3:
                // Extract features for testing
                extractFeatures(protocolToFilter,
                        pcapnames_test,
                        classes,
                        no_of_os_instances_test,
                        work_folder,
                        protocol,
                        useDerivedFeatures,
                        derivedFeaturesSuffixConsider,
                        derivedFeaturesSuffixIgnore,
                        derivedFeaturesSuffixInclude,
                        "pcap_files_test",
                        "test");
                break;
            case 4:
                // Select features using GA
                select_features(tsharkselected_features_list_path,
                        population_ga,
                        selected_features_file_path,
                        gaParameters);
                break;
            case 5:
                // Classify using GA features
                train_and_test(work_folder + "/features/" + protocol + "/train_merged.arff",
                        work_folder + "/features/" + protocol + "/",
                        selected_features_file_path,
                        true,
                        classifier,
                        gaParameters);
                break;
            case 6:
                // Classify using all the features
                train_and_test(work_folder + "/features/" + protocol + "/train_merged.arff",
                        work_folder + "/features/" + protocol + "/",
                        selected_features_file_path,
                        false,
                        classifier,
                        gaParameters);
                break;
            case 7:
                // Build model for ML from GA selected features
                build_model(work_folder + "/features/" + protocol + "/train_merged.arff",
                        work_folder + "/features/" + protocol + "/",
                        config_path,
                        protocol);
                break;
            case 8:
                test_packets_in_group(work_folder + "/features/" + protocol + "/test_merged.arff",
                        work_folder + "/features/",
                        k,
                        verbose,
                        config_path,
                        threshold_group);
                break;
//            case 9:
//                extract_examples_by_first_classifier(work_folder + "/features/" + protocol + "/train_merged.arff",
//                        work_folder + "/features/" + protocol + "/test_merged.arff",
//                        selected_features_file_path,
//                        true,
//                        work_folder + "/features/" + protocol + "/",
//                        classifier,
//                        weka_path,
//                        group,
//                        k,
//                        models);
//                break;
            default:
                System.out.println(ANSI_RED + "Unknown mode '" + mode + "' " + ANSI_GREEN + "Type -h to see the help menu." + ANSI_RESET);
                System.exit(0);
                break;
        }
    }

    public static void delete_file(String input) {
        File f1 = new File(input);
        boolean b = f1.delete();
    }

    public static void copy_file(String input, String output) {
        BufferedReader reader = null;
        BufferedWriter writer = null;

        try {
            reader = new BufferedReader(new FileReader(input));
            writer = new BufferedWriter(new FileWriter(output, false));

            String currentLine = reader.readLine();

            while (currentLine != null) {
                writer.write(currentLine);
                writer.newLine();

                currentLine = reader.readLine();
            }
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        finally {
            // Closing the resources
            try {
                if (reader != null)
                    reader.close();

                if(writer != null)
                    writer.close();
            }
            catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static void createAnalysisFile(String input, String output, ArrayList<String> derivedFeaturesSuffixConsider, ArrayList<String> derivedFeaturesSuffixIgnore, ArrayList<String> derivedFeaturesSuffixInclude) {
        BufferedReader reader = null;
        BufferedWriter writer = null;

        try {
            reader = new BufferedReader(new FileReader(input));
            writer = new BufferedWriter(new FileWriter(output, false));

            String currentLine = reader.readLine(); // read a line

            while (currentLine != null) { // for each line
                String[] tokens = currentLine.split(",");

                if (derivedFeaturesSuffixIgnore.contains(currentLine)) { // if it is behavior feature
                    writer.write(currentLine);
                    writer.newLine();
                }
                else {
                    writer.write(currentLine);
                    writer.newLine();

                    if (tokens.length == 1) { // if the feature does not have any commas (e.g. ,hexadecimal)
                        for (int i = 0; i < derivedFeaturesSuffixConsider.size(); i++) {
                            writer.write(currentLine + "__" + derivedFeaturesSuffixConsider.get(i));
                            writer.newLine();
                        }
                    } else { // if the feature contains commas (e.g. ,hexadecimal)
                        for (int i = 0; i < derivedFeaturesSuffixConsider.size(); i++) {
                            writer.write(tokens[0] + "__" + derivedFeaturesSuffixConsider.get(i));
                            for (int j = 1; j < tokens.length; j++) {
                                writer.write(",");
                                writer.write(tokens[j]);
                            }
                            writer.newLine();
                        }
                    }
                }

                currentLine = reader.readLine(); // read a line
            }
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        finally { // closing the resources
            try {
                if (reader != null)
                    reader.close();

                if(writer != null)
                    writer.close();
            }
            catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static void build_model(String trainfile_link, String path, String config_path, String protocol) {
        if (config_path.equals("")) {
            System.out.println("Error! Config file not provided!");
            System.exit(0);
        }

        new BuildModel().build_model(trainfile_link, path, config_path, protocol);
    }

    // Returns the number of lines in a file
    public static int get_no_of_lines(String filename) {
        int no_of_lines = 0;
        try {
            BufferedReader reader = new BufferedReader(new FileReader(filename));

            String line;
            while ((line = reader.readLine()) != null)
                if (!line.trim().isEmpty())
                    no_of_lines++;

            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return no_of_lines;
    }

    // Returns all the lines of a file in an ArrayList
    public static ArrayList<String> get_lines_from_file(String filename) {
        ArrayList<String> lines = new ArrayList<>();
        try {
            BufferedReader reader = new BufferedReader(new FileReader(filename));

            String line;
            while ((line = reader.readLine()) != null)
                if (!line.trim().isEmpty())
                    lines.add(line);

            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return lines;
    }

    // Prints the help screen
    public static void help() {
        System.out.println("SYSID Version: 1.0");
        System.out.println("Operating System Classifier using Machine Learning");
        System.out.println("University of Nevada, Reno");
        System.out.println("Nevada/USA 2016");
        System.out.println();
        System.out.println("AUTHOR");
        System.out.println("    System by   : Ahmet Aksoy & Mehmet H. Gunes");
        System.out.println("    Coded by    : Ahmet Aksoy");
        System.out.println();
        System.out.println("SYNOPSIS");
        System.out.println("    java -jar oscml.jar [OPTIONS]");
        System.out.println();
        System.out.println("OPTIONS");
        System.out.println("    -h     --help                Shows this page.");
        System.out.println("    -w     --work-folder         The direct path of the work folder. (default = the folder th jar file is in)");
        System.out.println("    -p     --protocol            The name of the protocol to be used.");
        System.out.println("    -g     --group               The number of packets to be classified at once.");
        System.out.println("    -m     --mode                The mode for the system to execute in.");
        System.out.println("    -c     --classifier          The algorithm to be used for the classification.");
        System.out.println("    -v     --validation          Specify the minimum number of folds for cross-validation. (default = 5)");
        System.out.println("    -i     --iteration           Specify the minimum number of iteration for Genetic Algorithm. (default = 5)");
        System.out.println("    -t     --train-only          Enable training-only. (default = on)");
        System.out.println("    -pg    --percentage-ga       Percentage of GA packets to be used (separately for training and testing.");
        System.out.println("    -os    --os-name             Name of the Operating System for single packet classification.");
        System.out.println();
        System.out.println("USAGE");
        System.out.println("    Step 1) Select non-null features:");
        System.out.println("            java -jar oscml.jar -w ./work_folder -p tcp -m 1");
        System.out.println("    Step 2) Extract features:");
        System.out.println("            java -jar oscml.jar -w ./work_folder -p tcp -m 2");
        System.out.println("    Step 3) Select features (using Genetic Algorithm):");
        System.out.println("            java -jar oscml.jar -w ./work_folder -p tcp -m 3");
        System.out.println();
        System.out.println("    e.g. Classify using cross-validation for the 'tcp' protocol:");
        System.out.println("    Step 4) Classify (using features selected by Genetic Algorithm):");
        System.out.println("            java -jar oscml.jar -w ./work_folder -p tcp -m 4");
        System.out.println("    Step 5) Classify (using all the features):");
        System.out.println("            java -jar oscml.jar -w ./work_folder -p tcp -m 5");
        System.out.println();
        System.out.println("    e.g. Classify packets either one by one or as a group at a time for the 'tcp' protocol:");
        System.out.println("    Step 4) Extract features:");
        System.out.println("            java -jar oscml.jar -w ./work_folder -p tcp -m 6 -os fedora_23_64bit");
        System.out.println("    Step 5) Classify (using features selected by Genetic Algorithm):");
        System.out.println("            java -jar oscml.jar -w ./work_folder -p tcp -m 7 -os fedora_23_64bit");
        System.out.println("    Step 6) Classify (using all the features):");
        System.out.println("            java -jar oscml.jar -w ./work_folder -p tcp -m 8 -os fedora_23_64bit");
    }

    // Merge files
    public static void merge_files(String folder, ArrayList<String> classes, int no_of_os_instances, String filename_prefix) {
        try {
            ArrayList<BufferedWriter> outfile = new ArrayList<>();

            for (int i = 0; i < no_of_os_instances; i++)
                outfile.add(new BufferedWriter(new FileWriter(new File(folder + "/" + filename_prefix + "_instance_" + (i+1)), true)));

            for (int i = 0; i < no_of_os_instances; i++) { // for each instance
                for (int j = 0; j < classes.size(); j++) { // for each OS
                    String current_file = folder + "/"+ filename_prefix + "_" + classes.get(j) + "_" + (i+1) + "_balanced";
                    if (new File(current_file).isFile()) { // if file exists
                        BufferedReader reader = new BufferedReader(new FileReader(current_file));

                        String line;
                        while ((line = reader.readLine()) != null) {
                            outfile.get(i).write(line);
                            outfile.get(i).newLine();
                            outfile.get(i).flush();
                        }

                        // Close file stream
                        reader.close();
                        new File(current_file).delete();
                    }
                }
            }

            // Close file stream
            for (int i = 0; i < no_of_os_instances; i++)
                outfile.get(i).close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Merge files
    public static void balance_packet_count(String folder, ArrayList<String> classes, int no_of_os_instances, String filename_prefix) {
        try {
            ArrayList<BufferedWriter> outfile = new ArrayList<>();

            for (int i = 0; i < no_of_os_instances; i++)
                for (int j = 0; j < classes.size(); j++) // for each OS
                    outfile.add(new BufferedWriter(new FileWriter(new File(folder + "/"+ filename_prefix + "_" + classes.get(j) + "_" + (i+1) + "_balanced"), true)));

            // determine the most number of packets available in files
            int no_of_maximum_packets_in_a_file = 0;
            for (int i = 0; i < no_of_os_instances; i++) { // for each instance
                for (int j = 0; j < classes.size(); j++) { // for each OS
                    String current_file = folder + "/"+ filename_prefix + "_" + classes.get(j) + "_" + (i+1) + "_uniq";
                    if (new File(current_file).isFile()) { // if file exists
                        int number_of_lines = get_no_of_lines(current_file);
                        if (number_of_lines > no_of_maximum_packets_in_a_file)
                            no_of_maximum_packets_in_a_file = number_of_lines;
                    }
                }
            }

            int outfile_array_pointer = 0;
            for (int i = 0; i < no_of_os_instances; i++) { // for each instance
                for (int j = 0; j < classes.size(); j++) { // for each OS
                    String current_file = folder + "/"+ filename_prefix + "_" + classes.get(j) + "_" + (i+1) + "_uniq";
                    if (new File(current_file).isFile()) { // if file exists
                        int no_of_packets_written = 0;

                        while (no_of_packets_written < no_of_maximum_packets_in_a_file) {
                            BufferedReader reader = new BufferedReader(new FileReader(current_file));

                            String line;
                            while (((line = reader.readLine()) != null) && (no_of_packets_written < no_of_maximum_packets_in_a_file)) {
                                outfile.get(outfile_array_pointer).write(line);
                                outfile.get(outfile_array_pointer).newLine();
                                outfile.get(outfile_array_pointer).flush();
                                no_of_packets_written++;
                            }

                            // Close file stream
                            reader.close();
                        }
                        new File(current_file).delete();
                    }
                    outfile_array_pointer++;
                }
            }

            // Close file stream
            for (int i = 0; i < no_of_os_instances; i++)
                outfile.get(i).close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void mergeTrainOrTestFiles(String folder, int no_of_os_instances, String filename_prefix) {
        try {
            BufferedWriter mergedfile = new BufferedWriter(new FileWriter(new File(folder + "/" + filename_prefix + "_merged"), true));
            for (int i = 0; i < no_of_os_instances; i++) { // for each instance
                String current_file = folder + "/"+ filename_prefix + "_instance_" + (i+1);
                BufferedReader reader = new BufferedReader(new FileReader(current_file));

                String line;
                while ((line = reader.readLine()) != null) {
                    mergedfile.write(line);
                    mergedfile.newLine();
                    mergedfile.flush();
                }

                // Close file stream
                reader.close();
            }

            // Close file stream
            mergedfile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static ArrayList<String> getAttributeLabels (String tshark_attributes_input_file) {
        ArrayList<String> attribute_names = new ArrayList<>();

        String inputFileCurrentLine = null; // holds the current line of the input file
        try {
            BufferedReader inputFile = new BufferedReader(new FileReader(tshark_attributes_input_file));

            // For each line in the input file
            while ((inputFileCurrentLine = inputFile.readLine()) != null)
                if (inputFileCurrentLine.trim().length() != 0)
                    attribute_names.add(inputFileCurrentLine);

            inputFile.close();
        } catch (IOException e2) {
            e2.printStackTrace();
        }

        return attribute_names;
    }

    // Extracts features for cross-validation
    public static void extractFeatures(String protocol_filter, ArrayList<String> pcapnames, ArrayList<String> classes, int no_of_os_instances, String work_folder, String protocol, boolean useDerivedFeatures, ArrayList<String> derivedFeaturesSuffixConsider, ArrayList<String> derivedFeaturesSuffixIgnore, ArrayList<String> derivedFeaturesSuffixInclude, String pcap_folder, String filename_prefix) {
        System.out.println(ANSI_BLUE + "Extracting features for protocol: " + ANSI_RED + protocol + ANSI_RESET);

        String tshark_attributes = work_folder + "/TsharkSelected/" + protocol;
        String protocol_file_path = work_folder + "/features/" + protocol;

        // Clean leftovers in the folder
        if (filename_prefix.equals("train"))
            deleteFolder(protocol_file_path);

        // Extract features, remove duplicates, sort randomly
        CountDownLatch latch = new CountDownLatch(pcapnames.size());

        try {
            for (int j = 0; j < pcapnames.size(); j++) { // for each pcap
                String source_file = protocol_file_path + "/" + filename_prefix + "_" + pcapnames.get(j);
                String pcap_file = work_folder + "/" + pcap_folder + "/" + pcapnames.get(j);
                String current_class = pcapnames.get(j);

                new ExtractFeaturesThread(protocol_filter, latch, current_class, protocol_file_path, tshark_attributes, source_file, pcap_file, useDerivedFeatures, derivedFeaturesSuffixConsider, derivedFeaturesSuffixIgnore, derivedFeaturesSuffixInclude).start();
            }

            latch.await(); // Current thread will get notified if all threads are done and thread will resume from wait() mode.
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        // Balance the packets
        balance_packet_count(protocol_file_path, classes, no_of_os_instances, filename_prefix);

        // Divide the genetic files
        merge_files(protocol_file_path, classes, no_of_os_instances, filename_prefix);

        // Include dummy examples for classes that are missing in the *_instance_* files
        addDummyExamplesForMissingClasses(no_of_os_instances, protocol_file_path, filename_prefix, tshark_attributes, classes);

        // Populate the arff file format for the instance files
        ArrayList<String> attribute_names_edited = getAttributeLabels(tshark_attributes);

        for (int i = 0; i < no_of_os_instances; i++)
            convertToArff(protocol_file_path + "/" + filename_prefix + "_instance_" + (i + 1), attribute_names_edited);

        // Populate the arff file format for the merged files
        if (filename_prefix.equals("train")) {
            mergeTrainOrTestFiles(protocol_file_path, no_of_os_instances, filename_prefix);
            convertToArff(protocol_file_path + "/" + filename_prefix + "_merged", attribute_names_edited);
        }

        // Remove the dummy files from .arff files
        for (int i = 0; i < no_of_os_instances; i++) {
            removeDummyExamples(protocol_file_path + "/" + filename_prefix + "_instance_" + (i + 1) + ".arff",
                    protocol_file_path + "/" + filename_prefix + "_instance_" + (i + 1) + ".arff_2",
                    tshark_attributes);
        }

        // Remove the dummy files from train_merged .arff file
        if (filename_prefix.equals("train")) {
            removeDummyExamples(protocol_file_path + "/" + filename_prefix + "_merged.arff",
                    protocol_file_path + "/" + filename_prefix + "_merged.arff_2",
                    tshark_attributes);
        }
    }

    public static void deleteFolder(String protocol_file_path) {
        File index = new File(protocol_file_path);
        if (index.exists()) { // if the folder exists, delete its content and itself
            String[]entries = index.list();
            for (String s: entries) {
                File currentFile = new File(index.getPath(),s);
                currentFile.delete();
            }
            new File(protocol_file_path).delete();
        }
    }

    public static void addDummyExamplesForMissingClasses(int no_of_os_instances, String protocol_file_path, String filename_prefix, String tshark_attributes, ArrayList<String> classes) {
        for (int i = 0; i < no_of_os_instances; i++) {
            HashMap<String, Integer> unique_classes = new HashMap<>();
            String input_file = protocol_file_path + "/" + filename_prefix + "_instance_" + (i + 1);
            String line;

            try {
                BufferedReader reader = new BufferedReader(new FileReader(input_file));
                while ((line = reader.readLine()) != null) {
                    if (!line.trim().isEmpty()) {
                        if (line.charAt(0) != '@') {
                            unique_classes.put(line.split(",")[line.split(",").length - 1], -1);
                        }
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }

            // for each class in the train file, find those that do not occur in testing data
            int no_of_tokens = get_no_of_lines(tshark_attributes);
            try {
                BufferedWriter output_text = new BufferedWriter(new FileWriter(new File(input_file), true));
                for (int j = 0; j < classes.size(); j++) {
                    if (!unique_classes.containsKey(classes.get(j))) {
                        String new_line = "";
                        for (int k = 0; k < no_of_tokens; k++)
                            new_line += "?,";
                        new_line += classes.get(j);
                        output_text.write(new_line);
                        output_text.newLine();
                        output_text.flush();
                    }
                }
                output_text.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static void removeDummyExamples(String input_file, String write_file, String tshark_attributes) {
        String line;

        try {
            BufferedReader reader = new BufferedReader(new FileReader(input_file));
            BufferedWriter output = new BufferedWriter(new FileWriter(new File(write_file), false));

            while ((line = reader.readLine()) != null) {
                if (line.trim().isEmpty() || line.charAt(0) == '@') {
                    output.write(line);
                    output.newLine();
                    output.flush();
                }
                else {
                    int no_of_tokens = get_no_of_lines(tshark_attributes);
                    String[] tokens = line.split(",");
                    int no_of_null = 0;
                    for (int j = 0; j < tokens.length-1; j++) {
                        if (tokens[j].equals("?"))
                            no_of_null++;
                    }
                    if (no_of_null < no_of_tokens) {
                        output.write(line);
                        output.newLine();
                        output.flush();
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        new File(input_file).delete();
        new File(write_file).renameTo(new File(input_file));
    }

    public static void convertToArff(String input, ArrayList<String> attribute_names_edited) {
        try {
            // load CSV
            CSVLoader loader = new CSVLoader();
            loader.setSource(new File(input));
            String[] options = new String[1];
            options[0] = "-H";
            loader.setOptions(options);
            Instances data = loader.getDataSet();
            for (int j = 0; j < attribute_names_edited.size(); j++)
                data.renameAttribute(j, attribute_names_edited.get(j).split(",")[0]);
            data.renameAttribute(attribute_names_edited.size(), "class");

            // save ARFF
            ArffSaver saver = new ArffSaver();
            saver.setInstances(data);
            saver.setFile(new File(input + ".arff"));
            saver.writeBatch();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Uses GA to select features
    public static void select_features(String protocol_file_name, int population, String selected_features_file_path, GAParameters gaParameters) {
        new GA().execute(protocol_file_name, population, selected_features_file_path, gaParameters);
        //new HillClimber().execute(weka_path, protocol_file_name, iteration, path_to_arffs, get_no_of_lines(protocol_file_name), weights, no_of_os_instances);
    }

    public static String get_indices(String features_file_path) {
        String parameters_to_be_deleted = "";

        try {
            BufferedReader in = new BufferedReader(new FileReader(features_file_path));
            parameters_to_be_deleted = in.readLine();
            in.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return parameters_to_be_deleted;
    }

    // Classifies using cross-validation
    public static void train_and_test(String train, String path, String selected_features_file_path, boolean ga_on, int classifier, GAParameters gaParameters) {
        ArrayList<ArrayList<Double>> results = new ArrayList<>();

        try {
            int i = 1;

            if (ga_on)
                System.out.println(ANSI_GREEN + "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ GA ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" + ANSI_RESET);
            else {
                System.out.println();
                System.out.println(ANSI_GREEN + "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ ALL +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" + ANSI_RESET);
            }
            System.out.println();

            while (true) {
                if (new File(path + "test_instance_" + i + ".arff").isFile()) { // if file exists
                    System.out.println(ANSI_RED + "FILE " + i + ": " + path + "test_instance_" + i + ".arff" + ANSI_RESET);
                    System.out.println();
                    results.add(new ClassifyML().train_test(train,
                            path + "test_instance_" + i + ".arff",
                            get_indices(selected_features_file_path),
                            classifier,
                            true,
                            false,
                            gaParameters,
                            null,
                            path));
                    System.out.println();
                    System.out.println(ANSI_BLUE + "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" + ANSI_RESET);
                    System.out.println();

                    i++;
                }
                else
                    break;
            }

            for (int j = 0; j < results.get(0).size(); j++) {
                int correct = 0;
                int incorrect = 0;

                for (int k = 0; k < results.size(); k++) {
                    if (results.get(k).get(j) == 1)
                        correct++;
                    else
                        incorrect++;
                }

                System.out.println("device " + j + ": " + correct + "/" + (correct+incorrect));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void test_packets_in_group(String test, String path, String k, boolean verbose, String config_path, double threshold_group) {
        if (config_path.equals("")) {
            System.out.println("Error! Config file not provided!");
            System.exit(0);
        }

        // Read protocol weights
        ArrayList<ProtocolWeight> protocol_weights = new ArrayList<>();
        ArrayList<FeatureOrder> feature_orders = new ArrayList<>();
        try {
            BufferedReader reader = new BufferedReader(new FileReader(config_path));

            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.trim().isEmpty()) {
                    if (line.equals("#"))
                        break;
                    else {
                        ProtocolWeight test_item = new ProtocolWeight();
                        test_item.name = line.split("\t")[0];
                        test_item.weight = Double.parseDouble(line.split("\t")[1]);
                        test_item.alg_code = Integer.parseInt(line.split("\t")[2]);
                        test_item.features_to_remove = line.split("\t")[4];
                        protocol_weights.add(test_item);
                    }
                }
            }

            while ((line = reader.readLine()) != null) {
                FeatureOrder test_item = new FeatureOrder();
                test_item.setProtocol_name(line);

                while ((line = reader.readLine()) != null) {
                    if (line.equals("*"))
                        break;
                    else
                        test_item.addFeatures(line);
                }

                feature_orders.add(test_item);
            }

            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        try {
            new ClassifyGroup().train_test(test, path, k, protocol_weights, verbose, feature_orders, threshold_group);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void extract_examples_by_first_classifier(String train, String test, String selected_features_file_path, boolean ga_on, String path, int classifier, String weka_path, int group, int k, Classifier[] models) {
        String parameters_to_be_deleted = ""; // concatenated string of features to be removed

        // get indices for features to be removed
        if (ga_on)
            parameters_to_be_deleted = get_indices(selected_features_file_path);

        try {
            new ClassifyMLextract().train_test(train, test, parameters_to_be_deleted, classifier, path, weka_path, group, k, models);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void classify_test(String path_to_arffs, String weka_path, String classifier, int cross_validation, int no_of_examples_in_a_group, String class_os, boolean GA) {
        new Classify().classify_test_one_by_one(weka_path, classifier, path_to_arffs, cross_validation, no_of_examples_in_a_group, class_os, GA);
    }

    public static void classify_test_all(String path_to_arffs, String weka_path, String classifier, int cross_validation, int no_of_examples_in_a_group, String class_os, boolean GA) {
        new Classify().classify_test_all(weka_path, classifier, path_to_arffs, cross_validation, no_of_examples_in_a_group, class_os, GA);
    }

    ////////////////////////////////////////////////
    // Determines the features which are non-null //
    ////////////////////////////////////////////////
    public static void findNonNullFeatures(String protocolToFilter, String tshark_features_list_path, String tsharkselected_features_list_path, ArrayList<String> pcapnames_train, String work_folder, int max_threads, boolean useDerivedFeatures, boolean useStreamFeatures, ArrayList<String> derivedFeaturesSuffixConsider, ArrayList<String> derivedFeaturesSuffixIgnore, ArrayList<String> derivedFeaturesSuffixInclude) {
        // Create the output folder if it doesn't already exist
        new File(work_folder + "/TsharkSelected/").mkdirs();

        try {
            // Get the number of classes
            int no_of_features = get_no_of_lines(tshark_features_list_path);
            ArrayList<String> fields = get_lines_from_file(tshark_features_list_path);
            BufferedWriter output_text = new BufferedWriter(new FileWriter(tsharkselected_features_list_path, false));

            int executed = 0;

            while (executed < no_of_features) {
                ExecutorService executor = Executors.newFixedThreadPool(Math.min(max_threads, no_of_features - executed));

                for (int i = executed; i < (executed + Math.min(max_threads, no_of_features - executed)); i++)
                    executor.execute(new FindNonNullFeaturesThread(protocolToFilter, fields.get(i), pcapnames_train, work_folder, output_text, i+1, no_of_features, useStreamFeatures)); // calling execute method of ExecutorService

                executor.shutdown();

                while (!executor.isTerminated()) {}

                executed += Math.min(max_threads, no_of_features - executed);
            }

            output_text.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Add analysis features to TsharkSelected
        if (useDerivedFeatures) {
            createAnalysisFile(tsharkselected_features_list_path, tsharkselected_features_list_path + "_analysis", derivedFeaturesSuffixConsider, derivedFeaturesSuffixIgnore, derivedFeaturesSuffixInclude);
            copy_file(tsharkselected_features_list_path, tsharkselected_features_list_path + "_original");
            delete_file(tsharkselected_features_list_path);
            copy_file(tsharkselected_features_list_path + "_analysis", tsharkselected_features_list_path);
            delete_file(tsharkselected_features_list_path + "_analysis");
        }
    }

    // Returns the names of files in a folder in an ArrayList
    public static ArrayList<String> get_files_in_folder(String folder) {
        ArrayList<String> results = new ArrayList<>();

        File[] files = new File(folder).listFiles(new FileFilter() {
            @Override
            public boolean accept(File file) {
                return !file.isHidden();
            }
        });

        // If this pathname does not denote a directory, then listFiles() returns null.
        for (File file : files)
            if (file.isFile())
                results.add(file.getName());

        return results;
    }

    // Returns the names of files in a folder in an ArrayList
    public static ArrayList<String> get_number_of_OSes(String folder) {
        ArrayList<String> results = new ArrayList<>();

        File[] files = new File(folder).listFiles(new FileFilter() {
            @Override
            public boolean accept(File file) {
                return !file.isHidden();
            }
        });

        // If this pathname does not denote a directory, then listFiles() returns null.
        for (File file : files)
            if (file.isFile())
                results.add(file.getName().split("_")[0]);

        return (ArrayList<String>) results.stream().distinct().collect(Collectors.toList()); // return unique list
    }
}

class FindNonNullFeaturesThread extends Thread {
    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_BLACK = "\u001B[30m";
    public static final String ANSI_RED = "\u001B[31m";
    public static final String ANSI_GREEN = "\u001B[32m";
    public static final String ANSI_YELLOW = "\u001B[33m";
    public static final String ANSI_BLUE = "\u001B[34m";
    public static final String ANSI_PURPLE = "\u001B[35m";
    public static final String ANSI_CYAN = "\u001B[36m";
    public static final String ANSI_WHITE = "\u001B[37m";
    private Thread t;
    private String threadName;
    private String packetProtocol;
    private String current_field;
    private int no_of_classes;
    private ArrayList<String> classes;
    private String work_folder;
    private BufferedWriter output_text;
    private int pos_of_current_field;
    private int no_of_fields;
    private boolean useStreamFeatures;

    FindNonNullFeaturesThread(String protocolToFilter, String current_field_input, ArrayList<String> classes, String work_folder, BufferedWriter output_text, int pos_of_current_field, int no_of_fields, boolean useStreamFeatures) {
        this.current_field = current_field_input;
        this.no_of_classes = classes.size();
        this.classes = classes;
        this.work_folder = work_folder;
        this.output_text = output_text;
        this.pos_of_current_field = pos_of_current_field;
        this.no_of_fields = no_of_fields;
        this.packetProtocol = protocolToFilter;
        this.useStreamFeatures = useStreamFeatures;

        threadName = current_field.split(",")[0];
    }

    // check this
    public void run() {
        ArrayList<String> output = new ArrayList<>();
        boolean write_to_file = false;
        String featureName = current_field.split(",")[0];

        if (current_field.split("_")[0].equals("stream") && useStreamFeatures)
            write_to_file = true;
        else {
            // For each class (OS), get the feature contents
            for (int i = 0; i < no_of_classes; i++) {
                String current_os = classes.get(i);

                if (packetProtocol == null)
                    output.addAll(new ExecuteSystemCommand().execute("tshark -n -r " + work_folder + "/pcap_files/" + current_os + " -Tfields -e " + featureName, false));
                else
                    output.addAll(new ExecuteSystemCommand().execute("tshark -n -r " + work_folder + "/pcap_files/" + current_os + " -Tfields -e " + featureName + " -Y " + packetProtocol, false));
            }

            // Check if the feature is null
            // Get unique entries
            ArrayList<String> listDistinct = (ArrayList<String>) output.stream().distinct().collect(Collectors.toList());

            if (listDistinct.size() > 1) { // if the outputs are not all null, write the feature name to the file (selected feature)
                if (current_field.split(",").length > 1) // Check if feature is hexadecimal
                    write_to_file = true;
                else {
                    // Check if feature contains : ...
                    boolean ignore = false;
                    for (int i = 0; i < listDistinct.size(); i++) {
                        if (listDistinct.get(i).contains(":")) {
                            ignore = true;
                            break;
                        }
                        else if ((listDistinct.get(i).length() - listDistinct.get(i).replace(".", "").length()) > 1) {
                            ignore = true;
                            break;
                        }
                    }

                    if (!ignore)
                        write_to_file = true;
                }
            }
        }

        if (write_to_file) {
            synchronized(output_text) {
                try {
                    output_text.write(current_field);
                    output_text.newLine();
                    output_text.flush();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        System.out.println(ANSI_BLUE + "Feature: " + ANSI_GREEN + featureName + ANSI_BLUE + " (" + pos_of_current_field + "/" + no_of_fields + ")" + ANSI_RESET);
    }

    public void start () {
        if (t == null) {
            t = new Thread (this, threadName);
            t.start ();
        }
    }
}

class ExtractFeaturesThread extends Thread {
    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_BLACK = "\u001B[30m";
    public static final String ANSI_RED = "\u001B[31m";
    public static final String ANSI_GREEN = "\u001B[32m";
    public static final String ANSI_YELLOW = "\u001B[33m";
    public static final String ANSI_BLUE = "\u001B[34m";
    public static final String ANSI_PURPLE = "\u001B[35m";
    public static final String ANSI_CYAN = "\u001B[36m";
    public static final String ANSI_WHITE = "\u001B[37m";
    private Thread t;
    private String threadName;
    private CountDownLatch latch;
    private String current_class;
    private String protocol_file_path;
    private String tshark_attributes;
    private String source_file;
    private String pcap_file;
    private String packetProtocol;
    private boolean useDerivedFeatures;
    private ArrayList<String> derivedFeaturesSuffixConsider;
    private ArrayList<String> derivedFeaturesSuffixIgnore;
    private ArrayList<String> derivedFeaturesSuffixInclude;

    ExtractFeaturesThread(String packetProtocol, CountDownLatch latch, String current_class, String protocol_file_path, String tshark_attributes, String source_file, String pcap_file, boolean useDerivedFeatures, ArrayList<String> derivedFeaturesSuffixConsider, ArrayList<String> derivedFeaturesSuffixIgnore, ArrayList<String> derivedFeaturesSuffixInclude) {
        this.latch = latch;
        this.current_class = current_class;
        this.protocol_file_path = protocol_file_path;
        this.tshark_attributes = tshark_attributes;
        this.source_file = source_file;
        this.pcap_file = pcap_file;
        this.packetProtocol = packetProtocol;
        this.useDerivedFeatures = useDerivedFeatures;
        this.derivedFeaturesSuffixConsider = derivedFeaturesSuffixConsider;
        this.derivedFeaturesSuffixIgnore = derivedFeaturesSuffixIgnore;
        this.derivedFeaturesSuffixInclude = derivedFeaturesSuffixInclude;
        threadName = current_class;
    }

    public void run() {
        new File(protocol_file_path).mkdirs(); // create a dedicated folder for the protocol

        // Extract features
        new OSExtractFeatures().extract(packetProtocol, tshark_attributes, source_file, pcap_file, current_class, useDerivedFeatures, derivedFeaturesSuffixConsider, derivedFeaturesSuffixIgnore, derivedFeaturesSuffixInclude);

        // Remove repeated examples from each examples file
        deleteDuplicates(source_file, source_file + "_uniq");

        new File(source_file).delete();

//        // Remove repeated examples from each examples file
//        deleteDuplicates(source_file, source_file + "_temp");
//        new File(source_file).delete();
//        // Randomly sort the contents of the files
//        sort_text_file(source_file + "_temp", source_file + "_uniq");
//        new File(source_file + "_temp").delete();

        System.out.println(ANSI_BLUE + "Class: " + ANSI_RED + current_class + ANSI_RESET);
        latch.countDown();
    }

    public void start() {
        if (t == null) {
            t = new Thread (this, threadName);
            t.start ();
        }
    }

    // Deletes duplicate lines in a file
    public void deleteDuplicates(String input_filename, String output_filename) {
        try {
            BufferedReader in = new BufferedReader(new FileReader(input_filename));
            Set<String> lines = new LinkedHashSet<>();

            for (String line; (line = in.readLine()) != null;)
                lines.add(line); // does nothing if duplicate is already added

            PrintWriter out = new PrintWriter(output_filename);

            for (String line : lines)
                out.println(line);

            in.close();
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void sortTextFile(String input, String output) {
        BufferedReader reader = null;
        BufferedWriter writer = null;

        //Create an ArrayList object to hold the lines of input file
        ArrayList<String> lines = new ArrayList<>();

        try {
            //Creating BufferedReader object to read the input file
            reader = new BufferedReader(new FileReader(input));

            //Reading all the lines of input file one by one and adding them into ArrayList
            String currentLine = reader.readLine();

            while (currentLine != null) {
                lines.add(currentLine);
                currentLine = reader.readLine();
            }

            // Sorting the ArrayList
            Collections.sort(lines);

            // Creating BufferedWriter object to write into output file
            writer = new BufferedWriter(new FileWriter(output));

            // Writing sorted lines into output file
            for (String line : lines) {
                writer.write(line);
                writer.newLine();
            }
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        finally {
            //Closing the resources
            try {
                if (reader != null)
                    reader.close();

                if(writer != null)
                    writer.close();
            }
            catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}

class ProtocolWeight {
    String name = "";
    double weight = 0.0;
    int alg_code = -1;
    String features_to_remove = "";
    int occurrence = 0;
}

class FeatureOrder {
    private String protocol_name = "";
    private ArrayList<String> features = new ArrayList<>();

    public String getProtocol_name() {
        return protocol_name;
    }

    public void setProtocol_name(String protocol_name) {
        this.protocol_name = protocol_name;
    }

    public int getFeaturesSize() { return features.size(); }

    public ArrayList<String> getFeatures() { return features; }

    public void addFeatures(String feature) {
        this.features.add(feature);
    }

    public void printFeatures() {
        System.out.print("[ ");
        for (int i = 0; i < this.features.size(); i++)
            System.out.print(this.features.get(i) + " ");
        System.out.println("]");
    }
}
