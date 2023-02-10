import weka.classifiers.Classifier;
import weka.core.Instances;
import weka.filters.Filter;
import weka.filters.unsupervised.attribute.Remove;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;

@SuppressWarnings("deprecation")
public class ClassifyGroup {
    public void train_test(String testfile_link, String path, String k, ArrayList<ProtocolWeight> protocol_weights, boolean verbose, ArrayList<FeatureOrder> feature_orders, double threshold_group) throws Exception {
        // Read test instances
        System.out.println("Reading the arff file (" + testfile_link + ")...");
        System.out.println();

        Instances testdata = new Instances(readDataFile(testfile_link));

        // set class indices for test data
        testdata.setClassIndex(testdata.numAttributes() - 1);

        // Get the class names
        String s = testdata.classAttribute().toString();
        String test = s.substring(s.indexOf("{") + 1, s.indexOf("}"));
        String[] classes = test.split(",");

        // print classes on the screen
        System.out.println("Classes in file: ");
        for (int i = 0; i < classes.length; i++)
            System.out.println(classes[i]);
        System.out.println();

        // determine class index
        int actual_class = -1; // initialize
        for (int i = 0; i < classes.length; i++) {
            if (classes[i].equals(k)) {
                actual_class = i;
                break;
            }
        }
        if (actual_class == -1) {
            System.out.println("Couldn't find the class name provided!");
            System.exit(0);
        }

        System.out.println("The class (selected) being processed is: " + classes[actual_class]);
        System.out.println("No. of original packets: " + testdata.numInstances());

        // remove instances belonging to other classes other than the one selected by the user
        int finalActual_class = actual_class;
        testdata.removeIf(i -> {
            return (((int) i.classValue()) != finalActual_class); // No return statement will break compilation
        });

        System.out.println("No. of packets for the selected class: " + testdata.numInstances());
        System.out.println();

        int numClasses = testdata.numClasses();

        // classify packets
        System.out.println("Classifying...");
        ArrayList<StringDouble> packet_labels = classify_packets(verbose, testdata, protocol_weights, feature_orders, path, classes); // stores the protocol, weight and the label for each packet

System.exit(0);

        // analyze groups
        for (int i = 70; i <= 100; i+=10) { // threshold
            for (int j = 0; j <= 100; j+=10) { // no. of packets in group
                if (j == 0) // increment it so it starts with 1 packet in group not 0
                    analyze_group(1, verbose, packet_labels, actual_class, numClasses, i);
                else
                    analyze_group(j, verbose, packet_labels, actual_class, numClasses, i);
            }
            // analyze all packets at once
            analyze_group(packet_labels.size(), verbose, packet_labels, actual_class, numClasses, i);
        }

//        // analyze unique protocol packets
//        analyze_unique_protocol_packets(verbose, packet_labels, actual_class, numClasses, 0);
//        for (int i = 70; i <= 100; i+=5)
//            analyze_unique_protocol_packets(verbose, packet_labels, actual_class, numClasses, i);
//        System.out.println("=======================================");
//        System.out.println();
    }

    public ArrayList<StringDouble> classify_packets(boolean verbose, Instances testdata, ArrayList<ProtocolWeight> protocol_weights, ArrayList<FeatureOrder> feature_orders, String path, String[] classes) {
        ArrayList<StringDouble> packet_labels = new ArrayList<>();

        try {
            Classifier model; // ML classification model

            // for each packet
            for (int i = 0; i < testdata.numInstances(); i++) {
                if (i > 0 && i % 1000 == 0)
                    System.out.println(i);

                // get the protocols that exist in the packet (frame.protocols field)
                if (verbose)
                    System.out.println("Protocols in the packet: " + testdata.get(i).stringValue(testdata.numAttributes() - 2));
                String[] packet_protocols = testdata.get(i).stringValue(testdata.numAttributes() - 2).split(":");

                ArrayList<StringDouble> pp_array = new ArrayList<>(); // holds the protocols to be considered (contains protocol name and weight)
                for (int pp = 0; pp < packet_protocols.length; pp++) { // for each protocol in the packet
                    for (int kp = 0; kp < protocol_weights.size(); kp++) { // for each known protocol
                        // check if the protocol of the packet occurs in the last part of the known protocol (e.g. ssl -> ssl OR ip_tcp_ssl, both are OK)
                        String last_protocol_in_known = protocol_weights.get(kp).name.split("_")[protocol_weights.get(kp).name.split("_").length - 1];
                        String last_protocol_in_packet = packet_protocols[pp];

                        if (last_protocol_in_known.equals(last_protocol_in_packet)) {
                            // check if this has already been added (NOT EFFICIENT)
                            boolean found = false;
                            for (int tp = 0; tp < pp_array.size(); tp++) {
                                if (pp_array.get(tp).protocol_used_to_test_instance.equals(protocol_weights.get(kp).name)) {
                                    found = true;
                                    break;
                                }
                            }

                            if (!found) {
                                StringDouble temp = new StringDouble();
                                temp.protocol_used_to_test_instance = protocol_weights.get(kp).name;
                                temp.weight = protocol_weights.get(kp).weight;
                                pp_array.add(temp);
                            }
                        }
                    }
                }

                // sort the protocols to be considered by the weight (descending)
                Collections.sort(pp_array, (bo1, bo2) -> {
                    if (bo1.weight < bo2.weight)
                        return 1;
                    else if (bo1.weight > bo2.weight)
                        return -1;
                    else
                        return 0;
                });

                // get the first item since it is sorted by weight in descending order
                StringDouble protocol_to_test = pp_array.get(0);

                if (verbose)
                    System.out.println("Protocol to test: " + protocol_to_test.protocol_used_to_test_instance + ", " + protocol_to_test.weight);

                // the path to the protocol's model
                String model_path = path + protocol_to_test.protocol_used_to_test_instance + "/model";

                // check if model exists
                File f = new File(model_path);
                if (!f.exists()) {
                    System.out.println("Model " + model_path + " doesn't exist!");
                    System.exit(0);
                }

                if (verbose)
                    System.out.println("Model path: " + model_path);

                // load the model
                model = (Classifier) weka.core.SerializationHelper.read(model_path);

                // Reorder features according to that of the model
                ArrayList<String> features = new ArrayList<>();
                for (int t = 0; t < feature_orders.size(); t++) {
                    if (feature_orders.get(t).getProtocol_name().equals(protocol_to_test.protocol_used_to_test_instance)) {
                        for (int tt = 0; tt < feature_orders.get(t).getFeaturesSize(); tt++)
                            features.add(feature_orders.get(t).getFeatures().get(tt));
                        break;
                    }
                }

                String order_for_the_features = "";

                for (int tt = 0; tt < features.size(); tt++)
                    for (int t = 0; t < testdata.numAttributes(); t++)
                        if (features.get(tt).equals(testdata.attribute(t).name()))
                            order_for_the_features += (t + 1) + ",";
                order_for_the_features += testdata.numAttributes(); // to remove the column containing protocol names in the instance

                Remove r = new Remove();
                r.setAttributeIndices(order_for_the_features);
                r.setInvertSelection(true);
                r.setInputFormat(testdata);
                Instances testdata2 = Filter.useFilter(testdata, r);
                testdata2.setClassIndex(testdata2.numAttributes() - 1); // set class indices for test data

//                if (verbose) {
//                    System.out.println("\t\t\t\tSorted features according to the model:");
//                    for (int t = 0; t < features.size(); t++)
//                        System.out.println("\t\t\t\t" + features.get(t));
//                    System.out.println();
//
//                    System.out.println("\t\t\t\tFeatures of the current packet:");
//                    for (int t = 0; t < testdata.numAttributes(); t++)
//                        System.out.println("\t\t\t\t " + (t + 1) + " -> " + testdata.attribute(t).name());
//                    System.out.println();
//                }


//                ArrayList<Attribute> original_attribute_names = new ArrayList<>();
//                for (int t = 0; t < testdata.numAttributes(); t++)
//                    original_attribute_names.add(new Attribute(testdata.attribute(t).name()));
//                original_attribute_names.add(new Attribute("@@class@@",testdata.instance(i).cl));
//                Instances testdata3 = new Instances("test", original_attribute_names, 0);
//                testdata3.attribute(0).
//                        testdata3.setClassIndex(testdata3.numAttributes() - 1);

//                if (verbose)
//                    for (int tt = 0; tt < testdata2.numAttributes(); tt++)
//                        System.out.println(testdata2.attribute(tt).name());

                // classify packet
                StringDouble temp = new StringDouble();
                temp.protocol_used_to_test_instance = protocol_to_test.protocol_used_to_test_instance; // set the protocol name used to classify this packet
                temp.weight = protocol_to_test.weight; // set the weight for the protocol used to classify this packet
                temp.predicted_label = (int) model.classifyInstance(testdata2.instance(i)); // set the predicted result
                packet_labels.add(temp);

                if (verbose) {
                    System.out.println("Packet: (" + temp.protocol_used_to_test_instance + ") " + testdata2.instance(i).toString());
                    System.out.println(temp.protocol_used_to_test_instance);
                    System.out.println(temp.weight);
                    System.out.println("Predicted: " + classes[temp.predicted_label]);
                    System.out.println();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return packet_labels;
    }

    public void analyze_group(int group, boolean verbose, ArrayList<StringDouble> packet_labels2, int actual_class, int no_of_classes, double threshold_group) {
        // remove packets which are below the threshold and also record the unique protocols
        ArrayList<StringDouble> packet_labels = new ArrayList<>();
        HashMap<String, Double> unique_protocols = new HashMap<String, Double>();
        for (int i = 0; i < packet_labels2.size(); i++) {
            if (packet_labels2.get(i).weight >= threshold_group) {
                packet_labels.add(packet_labels2.get(i));
                unique_protocols.put(packet_labels2.get(i).protocol_used_to_test_instance, packet_labels2.get(i).weight);
            }
        }

        // if packets are removed, fix the group size
        if (group > packet_labels.size())
            group = packet_labels.size();

        System.out.println("Number of packets in a group: " + group);
        System.out.println("Threshold: " + threshold_group);
        System.out.print("Protocols: ");
        for (String i : unique_protocols.keySet())
            System.out.print(i + " ");
        System.out.println();
        int correct = 0;
        int incorrect = 0;
        int total = 0;

        // for each group of packets
        for (int i = 0; i <= (packet_labels.size() - group); i++) { // for each group
            // Initialize the array which will contain the protocols and their occurrences for each class
            ArrayList<ArrayList<ProtocolWeight>> weights_for_classes = new ArrayList<>();  // # of classes -> # of protocols
            for (int j = 0; j < no_of_classes; j++) { // for as many as the number of classes
                ArrayList<ProtocolWeight> temp = new ArrayList<>();
                weights_for_classes.add(temp);
            }

            if (verbose)
                System.out.println("Group: [" + i + "," + (i + group - 1) + "]");

            for (int j = i; j < (i + group); j++) { // for each packet
                if (verbose)
                    System.out.println("\tPacket: " + j);

                // predict the packet with the model
                int result = packet_labels.get(j).predicted_label;
                if (verbose)
                    System.out.println("\t\t\tPredicted class label: " + result);

                // check if the current protocol has been added to the array for the class that it was classified for
                boolean found = false;
                for (int t = 0; t < weights_for_classes.get(result).size(); t++) {
                    if (weights_for_classes.get(result).get(t).name.equals(packet_labels.get(j).protocol_used_to_test_instance)) {
                        weights_for_classes.get(result).get(t).occurrence++;
                        found = true;
                    }
                }

                if (!found) { // if not, add it
                    ProtocolWeight temp = new ProtocolWeight();
                    temp.occurrence = 1;
                    temp.name = packet_labels.get(j).protocol_used_to_test_instance;
                    temp.weight = packet_labels.get(j).weight;
                    weights_for_classes.get(result).add(temp);
                }

                if (verbose)
                    System.out.println("\t\t\tActual class label: " + actual_class);
            }

            if (verbose) {
                System.out.println();
                System.out.println("\tDistribution:");

                for (int j = 0; j < weights_for_classes.size(); j++) { // for each class
                    System.out.println("\t\tClass: " + j);
                    for (int l = 0; l < weights_for_classes.get(j).size(); l++) { // for each protocol
                        System.out.println("\t\t\tProtocol: " + weights_for_classes.get(j).get(l).name);
                        System.out.println("\t\t\t\tWeight: " + weights_for_classes.get(j).get(l).weight);
                        System.out.println("\t\t\t\tOccurrence: " + weights_for_classes.get(j).get(l).occurrence);
                    }
                }
                System.out.println();
            }

            // decision making part
            ArrayList<Double> final_weights_for_classes = new ArrayList<>();

            for (int j = 0; j < weights_for_classes.size(); j++) { // for each class
                double overall_result = 0.0;

                for (int l = 0; l < weights_for_classes.get(j).size(); l++) { // for each protocol
                    double result = weights_for_classes.get(j).get(l).weight * weights_for_classes.get(j).get(l).occurrence;
                    overall_result += result;
                }

                final_weights_for_classes.add(overall_result);
            }

            if (verbose) {
                System.out.println();
                System.out.println("\tWeights:");

                for (int j = 0; j < final_weights_for_classes.size(); j++) // for each class
                    System.out.println("\t\t" + j + ": " + final_weights_for_classes.get(j));
            }

            int predicted_class = 0;
            for (int j = 0; j < final_weights_for_classes.size(); j++)
                if (final_weights_for_classes.get(j) > final_weights_for_classes.get(predicted_class))
                    predicted_class = j;

            if (verbose) {
                System.out.println();
                System.out.println("\tPredicted class is: " + predicted_class);
                System.out.println();
            }

            if (actual_class == predicted_class)
                correct++;
            else
                incorrect++;
            total++;
        }

        System.out.println("Correct: " + correct);
        System.out.println("Incorrect: " + incorrect);
        System.out.println("Total: " + total);
        System.out.println("Rate: " + (correct / (double) total) * 100);
        System.out.println();
    }

    public void analyze_unique_protocol_packets(boolean verbose, ArrayList<StringDouble> packet_labels2, int actual_class, int no_of_classes, double threshold_group) {
        HashMap<String, Double> unique_protocols = new HashMap<String, Double>();

        // remove packets which are below the threshold and also record the unique protocols
        ArrayList<StringDouble> packet_labels = new ArrayList<>();
        for (int i = 0; i < packet_labels2.size(); i++) {
            if (packet_labels2.get(i).weight >= threshold_group) {
                if (!unique_protocols.containsValue(packet_labels2.get(i).protocol_used_to_test_instance)) {
                    packet_labels.add(packet_labels2.get(i));
                    unique_protocols.put(packet_labels2.get(i).protocol_used_to_test_instance, packet_labels2.get(i).weight);
                }
            }
        }

        System.out.println("Threshold: " + threshold_group);
        System.out.print("Protocols: ");
        for (String i : unique_protocols.keySet())
            System.out.print(i + " ");
        System.out.println();
        int correct = 0;
        int incorrect = 0;
        int total = 0;

        // Initialize the array which will contain the protocols and their occurrences for each class
        ArrayList<ArrayList<ProtocolWeight>> weights_for_classes = new ArrayList<>();  // # of classes -> # of protocols
        for (int j = 0; j < no_of_classes; j++) { // for as many as the number of classes
            ArrayList<ProtocolWeight> temp = new ArrayList<>();
            weights_for_classes.add(temp);
        }

        for (int j = 0; j < packet_labels.size(); j++) { // for each packet
            if (verbose)
                System.out.println("\tPacket: " + j);

            // predict the packet with the model
            int result = packet_labels.get(j).predicted_label;
            if (verbose)
                System.out.println("\t\t\tPredicted class label: " + result);

            // check if the current protocol has been added to the array for the class that it was classified for
            boolean found = false;
            for (int t = 0; t < weights_for_classes.get(result).size(); t++) {
                if (weights_for_classes.get(result).get(t).name.equals(packet_labels.get(j).protocol_used_to_test_instance)) {
                    weights_for_classes.get(result).get(t).occurrence++;
                    found = true;
                }
            }

            if (!found) { // if not, add it
                ProtocolWeight temp = new ProtocolWeight();
                temp.occurrence = 1;
                temp.name = packet_labels.get(j).protocol_used_to_test_instance;
                temp.weight = packet_labels.get(j).weight;
                weights_for_classes.get(result).add(temp);
            }

            if (verbose)
                System.out.println("\t\t\tActual class label: " + actual_class);
        }

        if (verbose) {
            System.out.println();
            System.out.println("\tDistribution:");

            for (int j = 0; j < weights_for_classes.size(); j++) { // for each class
                System.out.println("\t\tClass: " + j);
                for (int l = 0; l < weights_for_classes.get(j).size(); l++) { // for each protocol
                    System.out.println("\t\t\tProtocol: " + weights_for_classes.get(j).get(l).name);
                    System.out.println("\t\t\t\tWeight: " + weights_for_classes.get(j).get(l).weight);
                    System.out.println("\t\t\t\tOccurrence: " + weights_for_classes.get(j).get(l).occurrence);
                }
            }
            System.out.println();
        }

        // decision making part
        ArrayList<Double> final_weights_for_classes = new ArrayList<>();

        for (int j = 0; j < weights_for_classes.size(); j++) { // for each class
            double overall_result = 0.0;

            for (int l = 0; l < weights_for_classes.get(j).size(); l++) { // for each protocol
                double result = weights_for_classes.get(j).get(l).weight * weights_for_classes.get(j).get(l).occurrence;
                overall_result += result;
            }

            final_weights_for_classes.add(overall_result);
        }

        if (verbose) {
            System.out.println();
            System.out.println("\tWeights:");

            for (int j = 0; j < final_weights_for_classes.size(); j++) // for each class
                System.out.println("\t\t" + j + ": " + final_weights_for_classes.get(j));
        }

        int predicted_class = 0;
        for (int j = 0; j < final_weights_for_classes.size(); j++)
            if (final_weights_for_classes.get(j) > final_weights_for_classes.get(predicted_class))
                predicted_class = j;

        if (verbose) {
            System.out.println();
            System.out.println("\tPredicted class is: " + predicted_class);
            System.out.println();
        }

        if (actual_class == predicted_class)
            correct++;
        else
            incorrect++;
        total++;

        System.out.println("Correct: " + correct);
        System.out.println("Incorrect: " + incorrect);
        System.out.println("Total: " + total);
        System.out.println("Rate: " + (correct / (double) total) * 100);
        System.out.println();
    }

    public static BufferedReader readDataFile(String filename) {
        BufferedReader inputReader = null;

        try {
            inputReader = new BufferedReader(new FileReader(filename));
        } catch (FileNotFoundException ex) {
            System.err.println("File not found: " + filename);
        }

        return inputReader;
    }

//    @SuppressWarnings("rawtypes")
//    public static double calculateAccuracy(FastVector predictions) {
//        double correct = 0;
//
//        for (int i = 0; i < predictions.size(); i++) {
//            NominalPrediction np = (NominalPrediction) predictions.elementAt(i);
//            if (np.predicted() == np.actual())
//                correct++;
//        }
//
//        return 100 * correct / predictions.size();
//    }
//
//    public static Instances removeFeatures(Instances inst, String indices) {
//        Instances newData = null;
//        try {
//            Remove remove = new Remove(); // new instance of filter
//            remove.setAttributeIndices(indices); // set options
//            remove.setInputFormat(inst); // inform filter about dataset **AFTER** setting options
//            newData = weka.filters.Filter.useFilter(inst, remove);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }   // apply filter
//        return newData;
//    }
}

class StringDouble {
    String protocol_used_to_test_instance = "";
    double weight = 0.0;
    int predicted_label = -1;
}
