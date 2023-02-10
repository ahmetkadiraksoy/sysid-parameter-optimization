import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class GAPopulation {
    GAIndividual[] individuals;
    GAParameters gaParameters;

    // Create a population
    public GAPopulation(int populationSize, boolean initialise, GAParameters gaParameters) {
        individuals = new GAIndividual[populationSize];
        this.gaParameters = gaParameters;

        // Initialise population
        if (initialise) {
            // Loop and create individuals
            for (int i = 0; i < size(); i++) {
                GAIndividual newIndividual = new GAIndividual(gaParameters);
                newIndividual.generateIndividual();
                saveIndividual(i, newIndividual);
            }
        }
    }

    // Getters
    public GAIndividual getIndividual(int index) {
        return individuals[index];
    }

    public GAIndividual getFittest() {
        ArrayList<GetFitnessThread> threads = new ArrayList<>();
        ExecutorService executor = Executors.newFixedThreadPool(gaParameters.max_threads);

        for (int i = 0; i < size(); i++)
            threads.add(new GetFitnessThread(individuals[i]));

        for (int i = 0; i < size(); i++)
            executor.execute(threads.get(i)); //calling execute method of ExecutorService

        executor.shutdown();
        while (!executor.isTerminated()) {}

        for (int i = 0; i < size(); i++)
            individuals[i] = threads.get(i).getIndividual();

        GAIndividual fittest = individuals[0];

        // loop trough individuals, find maximum fitness and return that
        for (int i = 0; i < size(); i++)
            if (fittest.getFitness() < individuals[i].getFitness())
                fittest = individuals[i];

        return fittest;
    }

    // Get population size
    public int size() {
        return individuals.length;
    }

    // Save individual
    public void saveIndividual(int index, GAIndividual indiv) {
        individuals[index] = indiv;
    }
}

class GetFitnessThread extends Thread {
    private Thread t;
    private GAIndividual current;

    GetFitnessThread(GAIndividual current) {
        this.current = current;
    }

    public void run() {
        @SuppressWarnings("unused")
        double temp = current.getFitness();
    }

    public GAIndividual getIndividual() {
        return current;
    }

    public void start () {
        if (t == null) {
            t = new Thread (this);
            t.start ();
        }
    }
}
