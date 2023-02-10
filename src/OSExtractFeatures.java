import java.io.*;
import java.math.RoundingMode;
import java.text.DecimalFormat;
import java.util.*;

public class OSExtractFeatures {
    public void extract(String protocol_filter, String tshark_attributes_input_file, String output_file, String pcap_file, String os, boolean useDerivedFeatures, ArrayList<String> derivedFeaturesSuffixConsider, ArrayList<String> derivedFeaturesSuffixIgnore, ArrayList<String> derivedFeaturesSuffixInclude) {
        ArrayList<ArrayList<String>> contents = new ArrayList<>(); // Create contents array

        // Get attribute labels
        ArrayList<String> attribute_names = getAttributeLabels(tshark_attributes_input_file);

        // Get number of attributes
        int no_of_attributes = attribute_names.size();

        String tshark_command_to_execute = "tshark -n -r " + pcap_file;
        // if filtering for a specific protocol is needed
        if (protocol_filter != null)
            tshark_command_to_execute += " -Y " + protocol_filter;
        tshark_command_to_execute += " -Tfields -e ";

        // Get number of packets
        int no_of_packets = new ExecuteSystemCommand().execute(tshark_command_to_execute + "frame.protocols", true).size();

        ///////////////////////////////////////
        // Read packet field data into array //
        ///////////////////////////////////////
        for (int index = 0; index < no_of_attributes; index++) { // for each attribute
            String header_name = attribute_names.get(index).split(",")[0];

            // skip if feature contains "__"
            if (!header_name.contains("__")) {
                // behavior-related features
                if (header_name.split("_")[0].equals("stream")) {
                    if (header_name.equals("stream_dst_no") || header_name.equals("stream_dst_cantor")) {
                        // ip.dst.no (no of unique ases that the device communicates with)
                        // ip.dst.cantor (cantor(multiplication) of the 2 most visited ases by the device)
                        contents.add(streamASRelatedFeatures(tshark_command_to_execute, header_name));
                    }
                    else if (header_name.equals("stream_synfin")) {
                        // number of packets between tcp syn and fin packets in the device
                        contents.add(streamSynFinFeatures(pcap_file, no_of_packets));
                    }
                    else if (header_name.equals("stream_iat")) {
                        // inter-arrival-time of packets
                        contents.add(streamIatFeatures(tshark_command_to_execute, header_name));
                    }
                    else if (header_name.equals("stream_synfintime")) {
                        // time between tcp syn and fin packets in the device
                        contents.add(streamSynFinTimeFeatures(tshark_command_to_execute, no_of_packets));
                    }
                    else if (header_name.equals("stream_packetlength")) {
                        // packet size
                        contents.add(streamPacketLengthFeatures(tshark_command_to_execute, header_name));
                    }
                }
                else {
                    // non-behavior-related features
                    contents.add(nonStreamFeatures(tshark_command_to_execute, header_name, attribute_names, index));
                }

                ArrayList<String> content = contents.get(contents.size()-1); // get the recently added item

                // generate derived features
                if (useDerivedFeatures && !derivedFeaturesSuffixIgnore.contains(header_name)) {
                    DerivedFeature values = getDerivedFeatures(content);

                    if (derivedFeaturesSuffixInclude.contains(header_name))
                        for (int i = 0; i < content.size(); i++)
                            content.set(i, "?");

                    for (int i = 0; i < derivedFeaturesSuffixConsider.size(); i++) {
                        ArrayList<String> contentToAdd = new ArrayList<>();
                        if (derivedFeaturesSuffixConsider.get(i).equals("min")) {
                            for (int j = 0; j < content.size(); j++)
                                contentToAdd.add(Double.toString(values.min));
                        }
                        else if (derivedFeaturesSuffixConsider.get(i).equals("median")) {
                            for (int j = 0; j < content.size(); j++)
                                contentToAdd.add(Double.toString(values.median));
                        }
                        else if (derivedFeaturesSuffixConsider.get(i).equals("mean")) {
                            for (int j = 0; j < content.size(); j++)
                                contentToAdd.add(values.mean);
                        }
                        else if (derivedFeaturesSuffixConsider.get(i).equals("max")) {
                            for (int j = 0; j < content.size(); j++)
                                contentToAdd.add(Double.toString(values.max));
                        }
                        else if (derivedFeaturesSuffixConsider.get(i).equals("mostcommon")) {
                            for (int j = 0; j < content.size(); j++)
                                contentToAdd.add(Double.toString(values.mostcommon));
                        }
                        else if (derivedFeaturesSuffixConsider.get(i).equals("variance")) {
                            for (int j = 0; j < content.size(); j++)
                                contentToAdd.add(values.variance);
                        }
                        else if (derivedFeaturesSuffixConsider.get(i).equals("interquartile")) {
                            for (int j = 0; j < content.size(); j++)
                                contentToAdd.add(Double.toString(values.interquartile));
                        }
                        else if (derivedFeaturesSuffixConsider.get(i).equals("stddeviation")) {
                            for (int j = 0; j < content.size(); j++)
                                contentToAdd.add(values.stddeviation);
                        }
                        else if (derivedFeaturesSuffixConsider.get(i).equals("uniquecount")) {
                            for (int j = 0; j < content.size(); j++)
                                contentToAdd.add(Integer.toString(values.uniquecount));
                        }
                        contents.add(contentToAdd);
                    }
                }
            }
        }

        if (no_of_attributes != contents.size()) {
            System.out.println("Size doesn't match!!!");
            System.exit(0);
        }

        // Add classes
        ArrayList<String> classes_append = new ArrayList<>();
        for (int j = 0; j < contents.get(0).size(); j++)
            classes_append.add(os.split("_")[0]);
        contents.add(classes_append);

        /////////////////////////
        // Remove null records //
        /////////////////////////
        for (int i = 0; i < contents.get(0).size(); i++) { // for each record
            int no_of_null = 0;

            for (int j = 0; j < (contents.size()-1); j++) // for each column (-1 to ignore class column)

                if (contents.get(j).get(i).equals("?"))
                    no_of_null++;

            if (no_of_null == no_of_attributes) { // remove null records
                for (int k = 0; k < contents.size(); k++) {
                    ArrayList<String> temp = contents.get(k);
                    temp.remove(i);
                    contents.set(k, temp);
                }
                i--;
            }
        }

        ////////////////////////////
        // Write examples to file //
        ////////////////////////////

        // Write the records to file
        try {
            FileWriter writer2 = new FileWriter(output_file, false);

            for (int i = 0; i < contents.get(0).size(); i++) { // for each record
                String output = "";

                // Prepare the record to be put to the file
                for (int j = 0; j < contents.size(); j++) { // for each column
                    String item = contents.get(j).get(i);
                    output = output + "," + item;
                }

                output = output.substring(1); // remove the first comma

                writer2.write(output + "\n");
                writer2.flush();
            }

            writer2.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static ArrayList<String> streamIatFeatures(String tshark_command_to_execute, String header_name) {
        ArrayList<String> content = new ExecuteSystemCommand().execute(tshark_command_to_execute + "frame.time_delta", true); // run tshark and get the output

        // check if output of tshark is empty
        if (content.size() == 0) {
            System.out.printf(header_name + " is empty!");
            System.exit(0);
        }

        // select the durations that are between 0 and 1 seconds
        for (int i = 0; i < content.size(); i++) {
            double item = Double.parseDouble(content.get(i));
            if (item < 0.0 || item > 1.0)
                content.set(i, "?");
        }

        return content;
    }

    public static ArrayList<String> streamPacketLengthFeatures(String tshark_command_to_execute, String header_name) {
        ArrayList<String> content = new ExecuteSystemCommand().execute(tshark_command_to_execute + "frame.len", true); // run tshark and get the output

        // check if output of tshark is empty
        if (content.size() == 0) {
            System.out.printf(header_name + " is empty!");
            System.exit(0);
        }

        return content;
    }

    public static ArrayList<String> streamSynFinFeatures(String pcap_file, int no_of_packets) {
        ArrayList<String> content = new ArrayList<>();
        for (int i = 0; i < no_of_packets; i++)
            content.add("?");

        ArrayList<String> tcp_syn = new ExecuteSystemCommand().execute("tshark -n -r " + pcap_file + " -Tfields -e tcp.flags.syn tcp", true);
        ArrayList<String> tcp_fin = new ExecuteSystemCommand().execute("tshark -n -r " + pcap_file + " -Tfields -e tcp.flags.fin tcp", true);

        // find unique number of packets between tcp syn and fin packets of a device
        int i = 0;
        int contentPos = 0;
        while (i < tcp_syn.size()) {
            int no_of_packets_in_between = 0;

            if (tcp_syn.get(i).equals("1")) {
                while (i < tcp_syn.size()) {
                    if (tcp_fin.get(i).equals("0")) {
                        no_of_packets_in_between++;
                        i++;
                    }
                    else
                        break;
                }
            }

            content.set(contentPos, Integer.toString(no_of_packets_in_between));
            contentPos++;

            i++;
        }

        return content;
    }

    public static ArrayList<String> streamSynFinTimeFeatures(String tshark_command_to_execute, int no_of_packets) {
        ArrayList<String> content = new ArrayList<>();
        for (int i = 0; i < no_of_packets; i++)
            content.add("?");

        ArrayList<String> tcp_syn = new ExecuteSystemCommand().execute(tshark_command_to_execute + "tcp.flags.syn tcp", true);
        ArrayList<String> tcp_fin = new ExecuteSystemCommand().execute(tshark_command_to_execute + "tcp.flags.fin tcp", true);
        ArrayList<String> epoch = new ExecuteSystemCommand().execute(tshark_command_to_execute + "frame.time_epoch tcp", true);

        // find unique distances of tcp syn and fin
        int i = 0;
        int contentPos = 0;
        while (i < tcp_syn.size()) {
            double time_in_between = 0.0;

            if (tcp_syn.get(i).equals("1")) {
                double start_time = Double.parseDouble(epoch.get(i));

                while (i < tcp_syn.size()) {
                    if (tcp_fin.get(i).equals("0"))
                        i++;
                    else {
                        double end_time = Double.parseDouble(epoch.get(i));
                        time_in_between = end_time - start_time;
                        break;
                    }
                }

                content.set(contentPos, Double.toString(time_in_between));
                contentPos++;
            }

            i++;
        }

        if (content.size() == 0)
            content.add("0.0");

        return content;
    }

    public static DerivedFeature getDerivedFeatures(ArrayList<String> content) {
        DerivedFeature values = new DerivedFeature();

        ArrayList<Double> contentDouble = new ArrayList<>();

        // copy output to double array
        for (int i = 0; i < content.size(); i++)
            if (!content.get(i).equals("?"))
                contentDouble.add(Double.parseDouble(content.get(i)));

        if (contentDouble.size() > 0) { // all column is not "?"
            // sort array
            Collections.sort(contentDouble);

            DecimalFormat df = new DecimalFormat("0.00");
            df.setRoundingMode(RoundingMode.UP);

            // find median
            if (contentDouble.size() % 2 == 0)
                values.median = (contentDouble.get(contentDouble.size() / 2) + contentDouble.get(contentDouble.size() / 2 - 1)) / 2.0;
            else
                values.median = contentDouble.get(contentDouble.size() / 2);

            // find mean
            double sum = 0.0;
            for (int i = 1; i < contentDouble.size(); i++)
                sum += contentDouble.get(i);
            double mean_full = sum / (double) contentDouble.size();
            values.mean = df.format(mean_full);

            // find min
            values.min = contentDouble.get(0); // initialize
            for (int i = 1; i < contentDouble.size(); i++) {
                if (contentDouble.get(i) < values.min)
                    values.min = contentDouble.get(i);
            }

            // find max
            values.max = contentDouble.get(0); // initialize
            for (int i = 1; i < contentDouble.size(); i++) {
                if (contentDouble.get(i) > values.max)
                    values.max = contentDouble.get(i);
            }

            // find most common & uniquecount
            HashMap<Double, Integer> mostcommon_array = new HashMap<>();
            for (int i = 0; i < contentDouble.size(); i++) {
                if (!mostcommon_array.containsKey(contentDouble.get(i)))
                    mostcommon_array.put(contentDouble.get(i), 1);
                else
                    mostcommon_array.put(contentDouble.get(i), mostcommon_array.get(contentDouble.get(i)) + 1);
            }
            int occurrence_of_most_common = 0;
            Iterator<Double> it = mostcommon_array.keySet().iterator();
            while (it.hasNext()) {
                double key = it.next();
                int value = mostcommon_array.get(key);

                if (value > occurrence_of_most_common)
                    values.mostcommon = key;

                values.uniquecount++;
            }

            // find variance & stddeviation
            double[] items = new double[contentDouble.size()];
            for (int i = 0; i < contentDouble.size(); i++)
                items[i] = contentDouble.get(i);
            double variance_full = new Statistics(items).getVariance();
            if (!Double.isNaN(variance_full))
                values.variance = df.format(variance_full);
            double stddeviation_full = new Statistics(items).getStdDev();
            if (!Double.isNaN(stddeviation_full))
                values.stddeviation = df.format(stddeviation_full);

            // find IQR
            double Q1 = contentDouble.get((int) ((double) contentDouble.size() * 0.25));
            double Q3 = contentDouble.get((int) ((double) contentDouble.size() * 0.75));
            values.interquartile = Q3 - Q1;
        }

        return values;
    }

    public static ArrayList<String> nonStreamFeatures(String tshark_command_to_execute, String header_name, ArrayList<String> attribute_names, int index) {
        ArrayList<String> content = new ExecuteSystemCommand().execute(tshark_command_to_execute + header_name, true); // run tshark and get the output

        // check if output of tshark is empty
        if (content.size() == 0) {
            System.out.printf(header_name + " is empty!");
            System.exit(0);
        }

        //////////////////////////////////////////////////////////////////
        // Fix items in arraylist (e.g. remove commas, convert hexa...) //
        //////////////////////////////////////////////////////////////////
        for (int i = 0; i < content.size(); i++) { // for each record
            String item = content.get(i);

            // Modify item
            item = item.split(",")[0]; // remove commas
            item = item.split(";")[0]; // remove semi-colons

            // Set to lower case
            item = item.toLowerCase();

            // remove whitespace
            item = item.replaceAll("\\s", "");

            // convert hexa to digit
            if (attribute_names.get(index).split(",").length > 1) // if extra information is added (,hexadecimal etc.)
                if (attribute_names.get(index).split(",")[1].equals("hexadecimal"))
                    if (!item.contains(".") && !item.equals("?"))
                        item = Integer.toString(hex2decimal(item));

            content.set(i, item);
        }

        return content;
    }

    public static ArrayList<String> streamASRelatedFeatures(String tshark_command_to_execute, String header_name) {
        // ip.dst.no (no of unique ases that the device communicates with)
        // ip.dst.cantor (cantor(multiplication) of the 2 most visited ases by the device)

        HashMap<Integer, Integer> unique_ases = new HashMap<>();
        HashMap<String, Integer> unique_ips = new HashMap<>();

        ArrayList<String> content = new ExecuteSystemCommand().execute(tshark_command_to_execute + "ip.dst", true); // run tshark and get the output

        // check if output of tshark is empty
        if (content.size() == 0) {
            System.out.printf(header_name + " is empty!");
            System.exit(0);
        }

        // Find unique ases and their occurrences
        for (int i = 0; i < content.size(); i++) {
            String ip_dst = content.get(i).split(",")[0];

            // find AS number
            int as = -1;

            if (!ip_dst.equals("") && !ip_dst.equals("?") && !ip_dst.split("\\.")[0].equals("10") && !ip_dst.split("\\.")[0].equals("0") && !ip_dst.split("\\.")[0].equals("255")) {
                if (unique_ips.containsKey(content.get(i)))
                    as = unique_ips.get(content.get(i));
                else {
                    as = Integer.parseInt(new ExecuteSystemCommand().execute("../asfinder/code ../asfinder/annoucements.pfx " + content.get(i), true).get(0));
                    unique_ips.put(content.get(i), as);
                }
            }

            // add the as to the list
            if (as != -1) {
                if (!unique_ases.containsKey(as)) // if the as has not been added before, add it with occurrence of 1
                    unique_ases.put(as, 1);
                else
                    unique_ases.put(as, unique_ases.get(as) + 1); // if the as has been added before, increment the occurrence
            }
        }

        // add the ases and their occurrences to this ArrayList
        ArrayList<IntInt> x = convertIntIntMapToIntIntArrayList(unique_ases);

        if (header_name.equals("stream_dst_no")) {
            for (int i = 0; i < content.size(); i++)
                content.set(i, Integer.toString(unique_ases.size()));
        }
        else if (header_name.equals("stream_dst_cantor")) {
            // Sort the ases by their occurrences
            sortIntIntArray(x);

            int cantor = 0;
            if (x.size() > 1)
                cantor = (((x.get(0).getKey() + x.get(1).getKey()) * (x.get(0).getKey() + x.get(1).getKey() + 1)) / 2) + x.get(1).getKey();
            else if (x.size() == 1)
                cantor = x.get(0).getKey();

            for (int i = 0; i < content.size(); i++)
                content.set(i, Integer.toString(cantor));
        }

        return content;
    }

    public static double getMostOccurring(ArrayList<Double> input) {
        HashMap<Double, Integer> most_common = new HashMap<>();

        for (int i = 0; i < input.size(); i++) {
            if (!most_common.containsKey(input.get(i)))
                most_common.put(input.get(i), 1);
            else
                most_common.put(input.get(i), most_common.get(input.get(i)) + 1);
        }

        ArrayList<IntDouble> x = new ArrayList<>();

        Iterator<Double> it = most_common.keySet().iterator();
        while (it.hasNext()) {
            double key = it.next();
            int value = most_common.get(key);

            IntDouble temp = new IntDouble();
            temp.key = key;
            temp.value = value;
            x.add(temp);
        }

        // sort
        for (int i = 0; i < x.size()-1; i++) {
            for (int j = i+1; j < x.size(); j++) {
                if (x.get(i).value < x.get(j).value) {
                    IntDouble temp = x.get(i);
                    x.set(i, x.get(j));
                    x.set(j, temp);
                }
                else if (x.get(i).value == x.get(j).value) {
                    if (x.get(i).key > x.get(j).key) {
                        IntDouble temp = x.get(i);
                        x.set(i, x.get(j));
                        x.set(j, temp);
                    }
                }
            }
        }

        double selected = 0;

        for (int i = 0; i < x.size(); i++)
            if (x.get(i).key > 0.0)
                selected = x.get(0).key;

        return selected;
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

    public static int hex2decimal(String s) {
        String digits = "0123456789ABCDEF";
        s = s.toUpperCase();
        int val = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            int d = digits.indexOf(c);
            val = 16*val + d;
        }
        return val;
    }

    public static boolean isAlphaNumeric(String s) {
        String pattern= "^[a-zA-Z0-9]*$";

        if (s.matches(pattern))
            return true;

        return false;
    }

    public static void sortIntIntArray(ArrayList<IntInt> x) {
        for (int i = 0; i < x.size() - 1; i++) {
            for (int j = i + 1; j < x.size(); j++) {
                if (x.get(i).getValue() < x.get(j).getValue()) {
                    IntInt temp = x.get(i);
                    x.set(i, x.get(j));
                    x.set(j, temp);
                } else if (x.get(i).getValue() == x.get(j).getValue()) {
                    if (x.get(i).getKey() > x.get(j).getKey()) {
                        IntInt temp = x.get(i);
                        x.set(i, x.get(j));
                        x.set(j, temp);
                    }
                }
            }
        }
    }

    public static ArrayList<IntInt> convertIntIntMapToIntIntArrayList(HashMap<Integer, Integer> map_input) {
        ArrayList<IntInt> x = new ArrayList<>();

        Iterator<Integer> it = map_input.keySet().iterator();
        while (it.hasNext()) { // for each as in the list
            int key = it.next();
            int value = map_input.get(key);

            IntInt temp = new IntInt();
            temp.setKey(key);
            temp.setValue(value);
            x.add(temp);
        }

        return x;
    }
}

class IntInt {
    private int key;
    private int value;

    public int getKey() { return key; }
    public int getValue() { return value; }
    public void setKey(int input) { key = input; }
    public void setValue(int input) { value = input; }
}

class IntDouble {
    double key;
    int value;
}

class DerivedFeature {
    double min = 0.0;
    double median = 0.0;
    String mean = "0.0";
    double max = 0.0;
    double mostcommon = 0.0;
    String variance = "0.0";
    double interquartile = 0.0;
    String stddeviation = "0.0";
    int uniquecount = 0;
}

//contents.add(new ExecuteSystemCommand().execute("tshark -n -r " + pcap_file + " -Tfields -e " + header_name + " tcp.flags.syn==1", true));
//contents.add(new ExecuteSystemCommand().execute("tshark -n -r " + pcap_file + " -Tfields -e " + header_name + " tcp.flags.syn==1 and tcp.flags.ack==0", true));
