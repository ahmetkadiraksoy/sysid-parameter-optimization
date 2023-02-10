import weka.classifiers.Classifier;
import weka.classifiers.evaluation.NominalPrediction;
import weka.core.FastVector;
import weka.core.Instances;
import weka.filters.unsupervised.attribute.Remove;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;

@SuppressWarnings("deprecation")
public class ClassifyMLextract {
    public static BufferedReader readDataFile(String filename) {
        BufferedReader inputReader = null;

        try {
            inputReader = new BufferedReader(new FileReader(filename));
        } catch (FileNotFoundException ex) {
            System.err.println("File not found: " + filename);
        }

        return inputReader;
    }

    @SuppressWarnings("rawtypes")
    public static double calculateAccuracy(FastVector predictions) {
        double correct = 0;

        for (int i = 0; i < predictions.size(); i++) {
            NominalPrediction np = (NominalPrediction) predictions.elementAt(i);
            if (np.predicted() == np.actual()) {
                correct++;
            }
        }

        return 100 * correct / predictions.size();
    }

    public static Instances removeFeatures(Instances inst, String indices) {
        Instances newData = null;
        try {
            Remove remove = new Remove();                         // new instance of filter
            remove.setAttributeIndices(indices);                           // set options
            remove.setInputFormat(inst);                          // inform filter about dataset **AFTER** setting options
            newData = weka.filters.Filter.useFilter(inst, remove);
        } catch (Exception e) {
            e.printStackTrace();
        }   // apply filter
        return newData;
    }

    //@SuppressWarnings({ "rawtypes", "unchecked" })
    public void train_test(String trainfile_link, String testfile_link, String indices, int classifier, String path, String weka_path, int group, int k, Classifier[] models) throws Exception {
        BufferedReader trainfile = readDataFile(trainfile_link);
        BufferedReader testfile = readDataFile(testfile_link);

        Instances traindata = new Instances(trainfile);
        Instances testdata = new Instances(testfile);

        if (!indices.equals("")) {
            traindata = removeFeatures(traindata, indices);
            testdata = removeFeatures(testdata, indices);
        }

        if ((traindata == null) || (testdata == null)) {
            System.out.println("ErRoR!");
            System.exit(0);
        }

        traindata.setClassIndex(traindata.numAttributes() - 1);
        testdata.setClassIndex(testdata.numAttributes() - 1);

        // Get class names
        String s = traindata.classAttribute().toString();
        String test = s.substring(s.indexOf("{") + 1, s.indexOf("}"));
        String[] classes = test.split(",");

        Classifier model = models[classifier];
        model.buildClassifier(traindata);

        // for each example, write it to the right file
        System.out.println("Class is: " + classes[k]);
        System.out.println();

        for (int i = 0; i < testdata.numInstances(); i++) {
//			int actual_result = (int) testdata.get(i).classValue();
            int result = (int) model.classifyInstance(testdata.instance(i));

//			System.out.println(result);
//			System.out.println(actual_result);
//			System.out.println();

            if (result == k)
                System.out.println(testdata.instance(i));

        }
    }
}