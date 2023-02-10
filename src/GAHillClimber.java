import java.io.*;
import java.util.ArrayList;
import java.util.Random;

public class GAHillClimber {
    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_BLACK = "\u001B[30m";
    public static final String ANSI_RED = "\u001B[31m";
    public static final String ANSI_GREEN = "\u001B[32m";
    public static final String ANSI_YELLOW = "\u001B[33m";
    public static final String ANSI_BLUE = "\u001B[34m";
    public static final String ANSI_PURPLE = "\u001B[35m";
    public static final String ANSI_CYAN = "\u001B[36m";
    public static final String ANSI_WHITE = "\u001B[37m";

    public void execute(String filename, int iteration, String work_folder, int no_of_features, GAParameters gaParameters) {
        ArrayList<String> solutions = new ArrayList<>();
        String solution = null;
        GAIndividual test = new GAIndividual(gaParameters);
        GAIndividual test2 = new GAIndividual(gaParameters);

        // Randomize
        for (int i = 0; i < no_of_features; i++)
            test.setGene(i, (byte) new Random().nextInt(2));

        // Add the solution to the arraylist
        solution = "";
        for (int i = 0; i < no_of_features; i++)
            solution += test.getGene(i);
        solutions.add(solution);

        double fitness = GAFitnessCalc.getFitness(test, gaParameters);

        while (true) {
            // flip bit
            test2.setGeneArray(test.getGeneArray());

            int pos = new Random().nextInt(no_of_features);
            if (test2.getGene(pos) == 1)
                test2.setGene(pos, (byte) 0);
            else
                test2.setGene(pos, (byte) 1);

            double temp_fitness =  GAFitnessCalc.getFitness(test2, gaParameters);

            if (temp_fitness > fitness) {
                fitness = temp_fitness;
                test.setGeneArray(test2.getGeneArray());

                // Add the solution to the arraylist
                solution = "";
                for (int i = 0; i < no_of_features; i++)
                    solution += test.getGene(i);
                solutions.add(solution);
            }

            // Print the solution
            int no_of_selected = 0;
            System.out.print(ANSI_RED + "Solution: " + ANSI_RESET);
            String tokens[] = solution.split("");
            for (int i = 0; i < tokens.length; i++) {
                if (tokens[i].equals("0"))
                    System.out.print(ANSI_CYAN + tokens[i] + ANSI_RESET);
                else {
                    no_of_selected++;
                    System.out.print(ANSI_BLUE + tokens[i] + ANSI_RESET);
                }
            }
            System.out.println(" " + ANSI_RED + "(" + no_of_selected + "/" + no_of_features + ")" + " " + fitness + "%" + ANSI_RESET);

            // Check loop break condition
            int no = 0;
            if (solutions.size() >= iteration)
            {
                String test3 = solutions.get(solutions.size() - 1);
                for (int i = 1; i < iteration; i++)
                    if (solutions.get((solutions.size() - 1) - i).equals(test3))
                        no++;

                if (no >= (iteration - 1))
                    break;
            }
        }

        // Concatenate solution into a string
        String[] tokens = solution.split("");

        String parameters_to_be_deleted = "";
        for (int i = 0; i < tokens.length; i++) {
            if (tokens[i].equals("0")) {
                parameters_to_be_deleted += (i+1);
                parameters_to_be_deleted += ",";
            }
        }
        parameters_to_be_deleted = parameters_to_be_deleted.substring(0, parameters_to_be_deleted.length()-1);

        // Write the concatenated string (selected feature numbers) to a file
        try {
            File file = new File(work_folder + "/selected_feature_nos_by_ga_alg_" + gaParameters.classifier);
            BufferedWriter output_text = new BufferedWriter(new FileWriter(file, false));

            output_text.write(parameters_to_be_deleted);
            output_text.newLine();
            output_text.flush();

            output_text.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Output names of features selected to the screen
        System.out.println();
        System.out.println(ANSI_BLUE + "Features selected by HC:" + ANSI_RESET);
        BufferedReader reader2;
        try {
            reader2 = new BufferedReader(new FileReader(filename));

            String line;
            int i = 0;
            while ((line = reader2.readLine()) != null) {
                if (!line.trim().isEmpty())
                    if (tokens[i].equals("1"))
                        System.out.println(ANSI_RED + line.split(",")[0] + ANSI_RESET);
                i++;
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
