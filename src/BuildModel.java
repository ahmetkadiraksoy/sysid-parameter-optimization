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
import weka.filters.unsupervised.attribute.Remove;

import java.io.*;

public class BuildModel {
    public void build_model(String trainfile_link, String path, String config_path, String protocol) {
        int classifier = -1;
        String indices = "";

        try {
            BufferedReader reader = new BufferedReader(new FileReader(config_path));

            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.trim().isEmpty()) {
                    if (line.equals("#"))
                        break;
                    else {
                        if (line.split("\t")[0].equals(protocol)) {
                            classifier = Integer.parseInt(line.split("\t")[2]);
                            indices = line.split("\t")[4];
                            break;
                        }
                    }
                }
            }

            reader.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("Classifier code: " + classifier);
        System.out.println("Indices removed: " + indices);

        BufferedReader trainfile = readDataFile(trainfile_link);
        Instances traindata = null;
        try {
            traindata = new Instances(trainfile);
        } catch (IOException e) {
            e.printStackTrace();
        }

        if ((traindata == null)) {
            System.out.println("ErRoR!");
            System.exit(0);
        }

        traindata = removeFeatures(traindata, indices);

        traindata.setClassIndex(traindata.numAttributes() - 1);

        // Use a set of classifiers
        Classifier[] models = {
                new J48(), // a decision tree
                new PART(),
                new DecisionTable(), // decision table majority classifier
                new DecisionStump(), // one-level decision tree
                new ZeroR(),
                new OneR(), // one-rule classifier
                new MultilayerPerceptron(), // neural network
                new RandomForest(),
                new SMO(),
                new JRip(),
                new Logistic(),
                new LinearRegression(),
                new BayesNet()
        };

        System.out.println("Building...");
        try {
            models[classifier].buildClassifier(traindata);
            new File(path + "model").delete();
            weka.core.SerializationHelper.write(path + "model", models[classifier]);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static Instances removeFeatures(Instances inst, String indices) {
        Instances newData = null;
        try {
            Remove remove = new Remove(); // new instance of filter
            remove.setAttributeIndices(indices); // set options
            remove.setInputFormat(inst); // inform filter about dataset **AFTER** setting options
            newData = weka.filters.Filter.useFilter(inst, remove);
        } catch (Exception e) {
            e.printStackTrace();
        }   // apply filter
        return newData;
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
}
