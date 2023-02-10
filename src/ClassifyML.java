import sun.rmi.runtime.Log;
import weka.classifiers.Classifier;
import weka.classifiers.Evaluation;
import weka.classifiers.bayes.BayesNet;
import weka.classifiers.evaluation.NominalPrediction;
import weka.classifiers.functions.LinearRegression;
import weka.classifiers.functions.Logistic;
import weka.classifiers.functions.MultilayerPerceptron;
import weka.classifiers.functions.SMO;
import weka.classifiers.rules.*;
import weka.classifiers.trees.DecisionStump;
import weka.classifiers.trees.J48;
import weka.classifiers.trees.RandomForest;
import weka.core.FastVector;
import weka.core.Instances;
import weka.filters.unsupervised.attribute.Remove;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.ArrayList;

@SuppressWarnings("deprecation")
public class ClassifyML {
    public static BufferedReader readDataFile(String filename) {
        BufferedReader inputReader = null;

        try {
            inputReader = new BufferedReader(new FileReader(filename));
        } catch (FileNotFoundException ex) {
            System.err.println("File not found: " + filename);
        }

        return inputReader;
    }

    public static Evaluation classify(Classifier model, Instances trainingSet, Instances testingSet) throws Exception {
        Evaluation evaluation = new Evaluation(trainingSet);

        model.buildClassifier(trainingSet);
        evaluation.evaluateModel(model, testingSet);

        return evaluation;
    }

    @SuppressWarnings("rawtypes")
    public static double calculateAccuracy(FastVector predictions) {
        double correct = 0;

        for (int i = 0; i < predictions.size(); i++) {
            NominalPrediction np = (NominalPrediction) predictions.elementAt(i);
            if (np.predicted() == np.actual())
                correct++;
        }

        return 100 * correct / predictions.size();
    }

    public static Instances removeFeatures(Instances inst, String indices) {
        Instances newData = null;
        try {
            Remove remove = new Remove();                         // new instance of filter
            remove.setAttributeIndices(indices);                  // set options
            remove.setInputFormat(inst);                          // inform filter about dataset **AFTER** setting options
            newData = weka.filters.Filter.useFilter(inst, remove);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return newData;
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    public ArrayList<Double> train_test(String trainfile_link, String testfile_link, String indices, int classifier, boolean verbose, boolean ga_mode, GAParameters gaParameters, GAIndividual individual, String path) throws Exception {
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

        BufferedReader trainfile = readDataFile(trainfile_link);
        BufferedReader testfile = readDataFile(testfile_link);

        Instances traindata = new Instances(trainfile);
        Instances testdata = new Instances(testfile);

        String parameters_to_be_deleted = convertIndicesToParametersToBeRemoved(indices, gaParameters.no_of_features);

        if (ga_mode) {
            // Remove features
            traindata = removeFeatures(traindata, parameters_to_be_deleted);
            testdata = removeFeatures(testdata, parameters_to_be_deleted);
        }

        if ((traindata == null) || (testdata == null)) {
            System.out.println("ErRoR!");
            System.exit(0);
        }

        traindata.setClassIndex(traindata.numAttributes() - 1);
        testdata.setClassIndex(testdata.numAttributes() - 1);

        // Set classifier parameters
        if (gaParameters.number_of_bits_for_parameters > 0)
            setClassifierParameters(models, indices, gaParameters.no_of_features, classifier, traindata.numInstances(), testdata.numInstances());

        // Collect every group of predictions for current model in a FastVector
        FastVector predictions = new FastVector();

        // For each training-testing split pair, train and test the classifier
        Evaluation validation = classify(models[classifier], traindata, testdata);
        predictions.appendElements(validation.predictions());

        // Uncomment to see the summary for each training-testing pair.
        if (verbose) {
            System.out.println(models[classifier].toString());
            System.out.println(validation.toSummaryString());
            System.out.println(validation.toMatrixString());
//            System.out.println(validation.toClassDetailsString());

            for (int i = 0; i < traindata.numClasses(); i++) {
                System.out.print("class: " + i);
                System.out.print(" tp: " + validation.numTruePositives(i));
                System.out.print(" tn: " + validation.numTrueNegatives(i));
                System.out.print(" fp: " + validation.numFalsePositives(i));
                System.out.print(" fn: " + validation.numFalseNegatives(i));
                System.out.println(" fmeasure: " + validation.fMeasure(i));
            }

            System.out.println("overall fmeasure: " + (validation.weightedFMeasure() * 100));
        }

        ArrayList<Double> results = new ArrayList<>();

        if (ga_mode) {
            results.add(validation.weightedFMeasure() * 100);
        }
        else {
            for (int i = 0; i < traindata.numClasses(); i++) {
                ArrayList<Double> class_results = new ArrayList<>();
                for (int j = 0; j < traindata.numClasses(); j++)
                    class_results.add(validation.confusionMatrix()[i][j]);
                double maxPosition = getMaxPosition(class_results);

                if ((int) maxPosition == i)
                    results.add(1.0);
                else
                    results.add(0.0);
            }
        }

        System.out.println("Building model...");
        try {
            models[classifier].buildClassifier(traindata);
            new File(path + "model").delete();
            weka.core.SerializationHelper.write(path + "model", models[classifier]);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return results;
    }

    float convertBinaryToDigit(int start, int end, double min, double max, String individual) {
        float result;
        double resultInNoOfBits = 0;

        int no_of_bits = end - start + 1;
        for (int i = 0; i < no_of_bits; i++)
            resultInNoOfBits += (Integer.parseInt(individual.split("")[start + i]) * Math.pow(2, (end - start) - i));

        double resultOutOf1 = resultInNoOfBits / Math.pow(2, no_of_bits);
        result = (float) ((max - min) * resultOutOf1) + (float) min;

        return result;
    }

    double getMaxPosition(ArrayList<Double> class_results) {
        // initiate
        int pos = 0;
        double max = class_results.get(pos);

        for (int i = 1; i < class_results.size(); i++) {
            if (class_results.get(i) > max) {
                max = class_results.get(i);
                pos = i;
            }
        }

        return pos;
    }

    // Extract features to be deleted and the ML parameters from chromosome
    String convertIndicesToParametersToBeRemoved(String indices, int no_of_features) {
        String parameters_to_be_deleted = "";
        String[] tokens = indices.substring(0, no_of_features).split("");

        for (int i = 0; i < no_of_features; i++) {
            if (tokens[i].equals("0")) {
                parameters_to_be_deleted += (i+1);
                parameters_to_be_deleted += ",";
            }
        }
        parameters_to_be_deleted = parameters_to_be_deleted.substring(0, parameters_to_be_deleted.length()-1); // remove the comma at the end
        return parameters_to_be_deleted;
    }

    void setClassifierParameters(Classifier[] models, String indices, int no_of_features, int classifier, int no_of_train_instances, int no_of_test_instances) {
        // set parameters
        if (classifier == 0) {
            if (indices.split("")[no_of_features] == "0")
                ((J48) models[0]).setCollapseTree(false);
            else
                ((J48) models[0]).setCollapseTree(true);

            if (indices.split("")[no_of_features + 1] == "0")
                ((J48) models[0]).setUnpruned(false);
            else
                ((J48) models[0]).setUnpruned(true);

            if (indices.split("")[no_of_features + 2] == "0")
                ((J48) models[0]).setReducedErrorPruning(false);
            else
                ((J48) models[0]).setReducedErrorPruning(true);

            if (indices.split("")[no_of_features + 3] == "0")
                ((J48) models[0]).setBinarySplits(false);
            else
                ((J48) models[0]).setBinarySplits(true);

            if (indices.split("")[no_of_features + 4] == "0")
                ((J48) models[0]).setSubtreeRaising(false);
            else
                ((J48) models[0]).setSubtreeRaising(true);

            if (indices.split("")[no_of_features + 5] == "0")
                ((J48) models[0]).setUseLaplace(false);
            else
                ((J48) models[0]).setUseLaplace(true);

            if (indices.split("")[no_of_features + 6] == "0")
                ((J48) models[0]).setUseMDLcorrection(false);
            else
                ((J48) models[0]).setUseMDLcorrection(true);

            if (indices.split("")[no_of_features + 7] == "0")
                ((J48) models[0]).setDoNotMakeSplitPointActualValue(false);
            else
                ((J48) models[0]).setDoNotMakeSplitPointActualValue(true);

            if (indices.split("")[no_of_features + 8] == "0")
                ((J48) models[0]).setSaveInstanceData(false);
            else
                ((J48) models[0]).setSaveInstanceData(true);

            if (indices.split("")[no_of_features + 9] == "0")
                ((J48) models[0]).setDoNotCheckCapabilities(false);
            else
                ((J48) models[0]).setDoNotCheckCapabilities(true);

            ((J48) models[0]).setConfidenceFactor(convertBinaryToDigit(10, 12, 0.0, 1.0, indices));

            ((J48) models[0]).setNumFolds((int) convertBinaryToDigit(13, 16, 2, Math.min(no_of_train_instances, no_of_test_instances), indices));

//            ((J48) models[0]).setMinNumObj((int) convertBinaryToDigit(17, 20, 0, 10, indices));
//            ((J48) models[0]).setSeed((int) convertBinaryToDigit(17, 20, 0, 100, indices));
//            ((J48) models[0]).setNumDecimalPlaces((int) convertBinaryToDigit(21, 23, 1, 10, indices));
        }
        else if (classifier == 1) {
            if (indices.split("")[no_of_features] == "0")
                ((PART) models[1]).setReducedErrorPruning(false);
            else
                ((PART) models[1]).setReducedErrorPruning(true);

            if (indices.split("")[no_of_features + 1] == "0")
                ((PART) models[1]).setBinarySplits(false);
            else
                ((PART) models[1]).setBinarySplits(true);

            if (indices.split("")[no_of_features + 2] == "0")
                ((PART) models[1]).setUnpruned(false);
            else
                ((PART) models[1]).setUnpruned(true);

            if (indices.split("")[no_of_features + 3] == "0")
                ((PART) models[1]).setUseMDLcorrection(false);
            else
                ((PART) models[1]).setUseMDLcorrection(true);

            if (indices.split("")[no_of_features + 4] == "0")
                ((PART) models[1]).setDoNotMakeSplitPointActualValue(false);
            else
                ((PART) models[1]).setDoNotMakeSplitPointActualValue(true);

            if (indices.split("")[no_of_features + 5] == "0")
                ((J48) models[0]).setDoNotCheckCapabilities(false);
            else
                ((J48) models[0]).setDoNotCheckCapabilities(true);

            ((PART) models[1]).setConfidenceFactor(convertBinaryToDigit(6, 8, 0.0, 1.0, indices));

            ((PART) models[1]).setNumFolds((int) convertBinaryToDigit(9, 12, 2, Math.min(no_of_train_instances, no_of_test_instances), indices));

//            ((PART) models[1]).setMinNumObj((int) convertBinaryToDigit(8, 11, 0, 100, indices));
//            ((PART) models[1]).setSeed((int) convertBinaryToDigit(12, 15, 0, 100, indices));
        }
        else if (classifier == 2) {
            if (indices.split("")[no_of_features] == "0")
                ((DecisionTable) models[2]).setUseIBk(false);
            else
                ((DecisionTable) models[2]).setUseIBk(true);

            if (indices.split("")[no_of_features + 1] == "0")
                ((DecisionTable) models[2]).setUseIBk(false);
            else
                ((DecisionTable) models[2]).setUseIBk(true);

            if (indices.split("")[no_of_features + 2] == "0")
                ((J48) models[0]).setDoNotCheckCapabilities(false);
            else
                ((J48) models[0]).setDoNotCheckCapabilities(true);

            ((DecisionTable) models[2]).setCrossVal((int) convertBinaryToDigit(3, 5, 1, Math.min(no_of_train_instances, no_of_test_instances), indices));
        }
        else if (classifier == 3) {
            if (indices.split("")[no_of_features] == "0")
                ((DecisionStump) models[3]).setDoNotCheckCapabilities(false);
            else
                ((DecisionStump) models[3]).setDoNotCheckCapabilities(true);

//            ((DecisionStump) models[3]).setNumDecimalPlaces((int) convertBinaryToDigit(2, 4, 1, 10, indices));
        }
        else if (classifier == 5) {
            if (indices.split("")[no_of_features] == "0")
                ((OneR) models[5]).setDoNotCheckCapabilities(false);
            else
                ((OneR) models[5]).setDoNotCheckCapabilities(true);

            ((OneR) models[5]).setMinBucketSize((int) convertBinaryToDigit(1, 3, 1, no_of_features, indices));

//            ((OneR) models[5]).setNumDecimalPlaces((int) convertBinaryToDigit(2, 4, 1, 10, indices));
        }

        else if (classifier == 6) {
            if (indices.split("")[no_of_features] == "0")
                ((MultilayerPerceptron) models[6]).setAutoBuild(false);
            else
                ((MultilayerPerceptron) models[6]).setAutoBuild(true);

            if (indices.split("")[no_of_features + 1] == "0")
                ((MultilayerPerceptron) models[6]).setNominalToBinaryFilter(false);
            else
                ((MultilayerPerceptron) models[6]).setNominalToBinaryFilter(true);

            if (indices.split("")[no_of_features + 2] == "0")
                ((MultilayerPerceptron) models[6]).setNormalizeNumericClass(false);
            else
                ((MultilayerPerceptron) models[6]).setNormalizeNumericClass(true);

            if (indices.split("")[no_of_features + 3] == "0")
                ((MultilayerPerceptron) models[6]).setNormalizeAttributes(false);
            else
                ((MultilayerPerceptron) models[6]).setNormalizeAttributes(true);

            if (indices.split("")[no_of_features + 4] == "0")
                ((MultilayerPerceptron) models[6]).setReset(false);
            else
                ((MultilayerPerceptron) models[6]).setReset(true);

            if (indices.split("")[no_of_features + 5] == "0")
                ((MultilayerPerceptron) models[6]).setDecay(false);
            else
                ((MultilayerPerceptron) models[6]).setDecay(true);

            if (indices.split("")[no_of_features + 6] == "0")
                ((MultilayerPerceptron) models[6]).setDoNotCheckCapabilities(false);
            else
                ((MultilayerPerceptron) models[6]).setDoNotCheckCapabilities(true);

            ((MultilayerPerceptron) models[6]).setLearningRate(convertBinaryToDigit(8, 9, 0, 1, indices));

            ((MultilayerPerceptron) models[6]).setMomentum(convertBinaryToDigit(10, 12, 0, 1, indices));

            ((MultilayerPerceptron) models[6]).setValidationSetSize((int) convertBinaryToDigit(13, 16, 0, 100, indices));

            ((MultilayerPerceptron) models[6]).setValidationThreshold((int) convertBinaryToDigit(17, 20, 1, 100, indices));
        }
        else if (classifier == 7) {
            if (indices.split("")[no_of_features + 0] == "0")
                ((RandomForest) models[7]).setBreakTiesRandomly(false);
            else
                ((RandomForest) models[7]).setBreakTiesRandomly(true);

            if (indices.split("")[no_of_features + 1] == "0")
                ((RandomForest) models[7]).setDoNotCheckCapabilities(false);
            else
                ((RandomForest) models[7]).setDoNotCheckCapabilities(true);

            if (indices.split("")[no_of_features + 2] == "0")
                ((RandomForest) models[7]).setRepresentCopiesUsingWeights(false);
            else
                ((RandomForest) models[7]).setRepresentCopiesUsingWeights(true);

            ((RandomForest) models[7]).setBagSizePercent(Math.round(convertBinaryToDigit(3, 6, 10, 100, indices)));

            ((RandomForest) models[7]).setNumIterations(Math.round(convertBinaryToDigit(7, 10, 0, 1000, indices)));

            ((RandomForest) models[7]).setNumExecutionSlots(Math.round(convertBinaryToDigit(11, 14, 0, 100, indices)));

            ((RandomForest) models[7]).setNumFeatures(Math.round(convertBinaryToDigit(15, 18, 0, 100, indices)));

            ((RandomForest) models[7]).setMaxDepth(Math.round(convertBinaryToDigit(19, 22, 1, 100, indices)));

//            if (indices.split("")[no_of_features + 3] == "0")
//                ((RandomForest) models[7]).setCalcOutOfBag(false);
//            else
//                ((RandomForest) models[7]).setCalcOutOfBag(true);
//            ((RandomForest) models[7]).setNumDecimalPlaces((int) convertBinaryToDigit(26, 28, 1, 10, indices));
//            ((RandomForest) models[7]).setSeed(Math.round(convertBinaryToDigit(18, 21, 0, 100, indices)));
        }
        else if (classifier == 8) {
            if (indices.split("")[no_of_features] == "0")
                ((SMO) models[8]).setDoNotCheckCapabilities(false);
            else
                ((SMO) models[8]).setDoNotCheckCapabilities(true);

            if (indices.split("")[no_of_features + 1] == "0")
                ((SMO) models[8]).setBuildCalibrationModels(false);
            else
                ((SMO) models[8]).setBuildCalibrationModels(true);

            ((SMO) models[8]).setToleranceParameter(convertBinaryToDigit(2, 5, 1, 100, indices));

            ((SMO) models[8]).setEpsilon(convertBinaryToDigit(6, 9, 0, 100, indices));

            ((SMO) models[8]).setC(convertBinaryToDigit(10, 13, 0, 100, indices));

            ((SMO) models[8]).setNumFolds((int) convertBinaryToDigit(14, 16, 2, Math.min(no_of_train_instances, no_of_test_instances), indices));

//            ((SMO) models[8]).setNumDecimalPlaces((int) convertBinaryToDigit(16, 18, 1, 10, indices));
//            if (indices.split("")[no_of_features + 2] == "0")
//                ((SMO) models[8]).setChecksTurnedOff(false);
//            else
//                ((SMO) models[8]).setChecksTurnedOff(true);

        }
        else if (classifier == 9) {
            if (indices.split("")[no_of_features] == "0")
                ((JRip) models[9]).setCheckErrorRate(false);
            else
                ((JRip) models[9]).setCheckErrorRate(true);

            if (indices.split("")[no_of_features + 1] == "0")
                ((JRip) models[9]).setUsePruning(false);
            else
                ((JRip) models[9]).setUsePruning(true);

            ((JRip) models[9]).setMinNo(convertBinaryToDigit(2, 5, 0, 100, indices));

            ((JRip) models[9]).setFolds((int) convertBinaryToDigit(6, 9, 2, Math.min(no_of_train_instances, no_of_test_instances), indices));

            ((JRip) models[9]).setOptimizations((int) convertBinaryToDigit(10, 13, 0, 100, indices));

//            if (indices.split("")[no_of_features + 2] == "0")
//                ((SMO) models[9]).setDoNotCheckCapabilities(false);
//            else
//                ((SMO) models[9]).setDoNotCheckCapabilities(true);
        }
        else if (classifier == 10) {
            if (indices.split("")[no_of_features] == "0")
                ((Logistic) models[10]).setDoNotCheckCapabilities(false);
            else
                ((Logistic) models[10]).setDoNotCheckCapabilities(true);

            if (indices.split("")[no_of_features + 1] == "0")
                ((Logistic) models[10]).setUseConjugateGradientDescent(false);
            else
                ((Logistic) models[10]).setUseConjugateGradientDescent(true);

            ((Logistic) models[10]).setRidge(convertBinaryToDigit(2, 5, 0, 100, indices));

            ((Logistic) models[10]).setMaxIts((int) convertBinaryToDigit(6, 9, 0, 1000, indices));
        }
        else if (classifier == 12) {
            if (indices.split("")[no_of_features] == "0")
                ((BayesNet) models[12]).setUseADTree(false);
            else
                ((BayesNet) models[12]).setUseADTree(true);

            if (indices.split("")[no_of_features + 1] == "0")
                ((BayesNet) models[12]).setDoNotCheckCapabilities(false);
            else
                ((BayesNet) models[12]).setDoNotCheckCapabilities(true);

//            ((BayesNet) models[12]).setNumDecimalPlaces((int) convertBinaryToDigit(2, 4, 1, 10, indices));
        }
    }
}
