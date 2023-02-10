import java.io.*;
import java.util.ArrayList;

public class GA {
    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_BLACK = "\u001B[30m";
    public static final String ANSI_RED = "\u001B[31m";
    public static final String ANSI_GREEN = "\u001B[32m";
    public static final String ANSI_YELLOW = "\u001B[33m";
    public static final String ANSI_BLUE = "\u001B[34m";
    public static final String ANSI_PURPLE = "\u001B[35m";
    public static final String ANSI_CYAN = "\u001B[36m";
    public static final String ANSI_WHITE = "\u001B[37m";

    public void execute(String filename, int population_size, String selected_features_file_path, GAParameters gaParameters) {
        // Create an initial population
        GAPopulation myPop = new GAPopulation(population_size, true, gaParameters);
        ArrayList<String> solutions = new ArrayList<>();
        String solution;

        int noOfFeatures = gaParameters.no_of_features;

        while (true) {
            GAIndividual fittest = myPop.getFittest();
            solution = fittest.toString();

            // Add the solution to the arraylist
            solutions.add(solution);

            // Print the solution
            int no_of_selected = 0;
            System.out.print(ANSI_RED + "Solution: " + ANSI_RESET);
            String[] tokens = solution.split("");

            // print bits in color
            for (int i = 0; i < noOfFeatures; i++) {
                if (tokens[i].equals("0"))
                    System.out.print(ANSI_CYAN + tokens[i] + ANSI_RESET);
                else {
                    no_of_selected++;
                    System.out.print(ANSI_BLUE + tokens[i] + ANSI_RESET);
                }
            }
            System.out.print(" ");
            for (int i = noOfFeatures; i < noOfFeatures + gaParameters.number_of_bits_for_parameters; i++) {
                if (tokens[i].equals("0"))
                    System.out.print(ANSI_CYAN + tokens[i] + ANSI_RESET);
                else
                    System.out.print(ANSI_BLUE + tokens[i] + ANSI_RESET);
            }

            System.out.println(" " + ANSI_RED + "(" + no_of_selected + "/" + noOfFeatures + ")" + " " + fittest.getFitness() + "%" + ANSI_RESET);

            // Check loop break condition
            int no = 0;
            if (solutions.size() >= gaParameters.iteration) {
                String test = solutions.get(solutions.size() - 1);
                for (int i = 1; i < gaParameters.iteration; i++)
                    if (solutions.get((solutions.size() - 1) - i).equals(test))
                        no++;

                if (no >= (gaParameters.iteration - 1))
                    break;
            }

            myPop = GAAlgorithm.evolvePopulation(myPop, gaParameters);
        }

        // Write the the chromosome to a file
        try {
            System.out.println();

            System.out.println(ANSI_RED + "Model path: " + ANSI_RESET + ANSI_BLUE + selected_features_file_path + ANSI_RESET);
            File file = new File(selected_features_file_path);
            BufferedWriter output_text = new BufferedWriter(new FileWriter(file, false));

            output_text.write(solution);
            output_text.newLine();
            output_text.flush();

            output_text.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Output names of features selected to the screen
        System.out.println();
        System.out.println(ANSI_RED + "Names of the selected features by GA:" + ANSI_RESET);
        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader(filename));

            String[] tokens = solution.split("");

            String line;
            int i = 0;
            while ((line = reader.readLine()) != null) {
                if (!line.trim().isEmpty())
                    if (tokens[i].equals("1"))
                        System.out.println(ANSI_BLUE + line.split(",")[0] + ANSI_RESET);
                i++;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Extract features to be deleted and to be kept
        String[] temp = convertIndicesToParametersToBeRemovedAndToStay(solution, noOfFeatures);
        String parameters_to_be_deleted = temp[0];
        String parameters_to_stay = temp[1];

        System.out.println();
        System.out.print(ANSI_RED + "Indices of selected features by GA: " + ANSI_RESET);
        System.out.println(ANSI_BLUE + parameters_to_stay + ANSI_RESET);
        System.out.print(ANSI_RED + "Indices of removed features by GA: " + ANSI_RESET);
        System.out.println(ANSI_BLUE + parameters_to_be_deleted + ANSI_RESET);
        System.out.println();
        System.out.println(ANSI_RED + "=====================================================" + ANSI_RESET);
        System.out.println();
    }

    String[] convertIndicesToParametersToBeRemovedAndToStay(String solution, int no_of_features) {
        String[] result = {"", ""};

        // Concatenate solution into a string
        String[] tokens = solution.split("");

        String parameters_to_be_deleted = "";
        String parameters_to_stay = "";
        for (int i = 0; i < no_of_features; i++) {
            if (tokens[i].equals("0")) {
                parameters_to_be_deleted += (i+1);
                parameters_to_be_deleted += ",";
            }
            else if (tokens[i].equals("1")) {
                parameters_to_stay += (i+1);
                parameters_to_stay += ",";
            }
        }
        if (!parameters_to_be_deleted.equals("")) // if there exist features to be removed
            parameters_to_be_deleted = parameters_to_be_deleted.substring(0, parameters_to_be_deleted.length()-1); // remove the comma at the end
        parameters_to_stay = parameters_to_stay.substring(0, parameters_to_stay.length()-1); // remove the comma at the end

        result[0] = parameters_to_be_deleted;
        result[1] = parameters_to_stay;

        return result;
    }
}
