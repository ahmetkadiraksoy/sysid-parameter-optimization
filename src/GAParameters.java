import java.util.ArrayList;

public class GAParameters {
    public String weights;
    public int classifier;
    public int iteration;
    public int no_of_features;
    public int no_of_os_instances;
    public String work_folder;
    public int max_threads;
    public int tournamentSize;
    public double uniformRate;
    public double mutationRate;
    public int number_of_bits_for_parameters = 2;
    public ArrayList<PreCalculatedGenes> preCalculatedGenes;
}

class PreCalculatedGenes {
    public byte[] genes;
    public double fitness = 0;
}