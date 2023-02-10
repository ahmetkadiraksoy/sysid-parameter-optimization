import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;

public class GAFitnessCalc {
    // Calculate individuals' fitness by comparing it to our candidate solution
    static double getFitness(GAIndividual individual, GAParameters gaParameters) {
        // check if this gene has already been calculated before
        synchronized (gaParameters) {
            for (int i = 0; i < gaParameters.preCalculatedGenes.size(); i++) {
                if (Arrays.equals(individual.getGeneArray(), gaParameters.preCalculatedGenes.get(i).genes)) {
                    return gaParameters.preCalculatedGenes.get(i).fitness;
                }
            }
        }

        String weight_tokens[] = gaParameters.weights.split(",");

        ////////////////
        // Parameters //
        ////////////////
        BufferedReader reader;
        int no_of_features = gaParameters.no_of_features;
        int no_of_features_selected = 0;
        double overall_performance_sum = 0;
        String parameters_to_be_deleted = ""; // concatenated string of features to be removed

        //////////////////////////////////////////////////////////////////////////////
        // Among the selected features, find the ones which contain all null values //
        // (those which appear as string in the arff file) and set them in the 'individual' to 0
        //////////////////////////////////////////////////////////////////////////////
        for (int i = 0; i < no_of_features; i++) { // for each feature
            if (individual.getGene(i) == 1) { // if this feature is not selected to be removed by GA
                no_of_features_selected++;
                int count = 0;
                for (int j = 0; j < gaParameters.no_of_os_instances; j++) { // for each instance
                    boolean feature_is_null = true;
                    // check if this feature is all null (string in arff)
                    try {
                        reader = new BufferedReader(new FileReader(gaParameters.work_folder + "/train_instance_" + (j+1)));

                        String line;
                        while ((line = reader.readLine()) != null) {
                            if (!line.trim().isEmpty()) {
                                String tokens[] = line.split(",");
                                if (!(tokens[i].equals("?"))) {
                                    feature_is_null = false;
                                    break;
                                }
                            }
                        }

                        if (feature_is_null) {
                            count++;
                            break;
                        }
                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }

                // if all null, then set it to be removed in the 'parameters_to_be_deleted'
                if (count > 0)
                    individual.setGene(i, (byte) 0);
            }
        }

        //////////////////////////////////////////////////////
        // Check if all features are selected to be removed //
        //////////////////////////////////////////////////////
        int no_of_zeros_in_chromosome = 0;
        for (int i = 0; i < no_of_features; i++) // for each feature
            if (individual.getGene(i) == 0)
                no_of_zeros_in_chromosome++;

        // If all features are selected to be removed, return 0's
        if (no_of_zeros_in_chromosome == no_of_features)
            return 0;

        // If all features are not selected to be removed
        if (no_of_zeros_in_chromosome > 0) {
            parameters_to_be_deleted = individual.toString();
        }

        ////////////////
        // TRAIN TEST //
        ////////////////
        for (int test_instance_no = 0; test_instance_no < gaParameters.no_of_os_instances; test_instance_no++) { // for each instance
            double performance_sum = 0;

            // For each test instance
            for (int train_instance_no = 0; train_instance_no < gaParameters.no_of_os_instances; train_instance_no++) {
                if (train_instance_no != test_instance_no) {
                    try {
                        performance_sum += new ClassifyML().train_test(gaParameters.work_folder + "/train_instance_" + (train_instance_no+1) + ".arff",
                                gaParameters.work_folder + "/train_instance_" + (test_instance_no+1) + ".arff",
                                parameters_to_be_deleted,
                                gaParameters.classifier,
                                false,
                                true,
                                gaParameters,
                                individual,
                                "").get(0);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }

            overall_performance_sum += performance_sum / (gaParameters.no_of_os_instances - 1);
        }

        double result = overall_performance_sum / gaParameters.no_of_os_instances;

        ////////////////////////
        // Return the results //
        ////////////////////////
        double classification_result = result * Double.parseDouble(weight_tokens[0]);
        double feature_result = (((no_of_features - no_of_features_selected) / (double) no_of_features) * 100) * Double.parseDouble(weight_tokens[1]);
        double result_to_return = classification_result + feature_result;

        // add the gene to precalculated set
        synchronized (gaParameters) {
            boolean found = false;
            for (int i = 0; i < gaParameters.preCalculatedGenes.size(); i++) {
                if (Arrays.equals(individual.getGeneArray(), gaParameters.preCalculatedGenes.get(i).genes)) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                PreCalculatedGenes test = new PreCalculatedGenes();
                test.genes = new byte[gaParameters.no_of_features];
                for (int i = 0; i < gaParameters.no_of_features; i++)
                    test.genes[i] = individual.getGeneArray()[i];
                test.fitness = result_to_return;
                gaParameters.preCalculatedGenes.add(test);
            }
        }

        return result_to_return;
    }
}
