public class GAIndividual {
    private byte[] genes;
    private double fitness = 0;
    private boolean has_run = false;
    GAParameters gaParameters;

    public GAIndividual(GAParameters gaParameters) {
        this.genes = new byte[gaParameters.no_of_features + gaParameters.number_of_bits_for_parameters];
        this.gaParameters = gaParameters;
    }

    // Create a random individual
    public void generateIndividual() {
        for (int i = 0; i < size(); i++)
            genes[i] = (byte) Math.round(Math.random());
    }

    public byte[] getGeneArray() {
        return genes;
    }

    public void setGeneArray(byte[] input) {
        this.genes = input;
    }

    public byte getGene(int index) {
        return genes[index];
    }

    public void setGene(int index, byte value) {
        genes[index] = value;
    }

    public int size() {
        return genes.length;
    }

    public double getFitness() {
        if (!has_run) {
            fitness = GAFitnessCalc.getFitness(this, gaParameters);
            has_run = true;
        }
        return fitness;
    }

    @Override
    public String toString() {
        String geneString = "";

        for (int i = 0; i < size(); i++)
            geneString += getGene(i);

        return geneString;
    }
}
