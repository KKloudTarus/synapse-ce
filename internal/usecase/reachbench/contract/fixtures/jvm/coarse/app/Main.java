import reachbench.direct.DirectDependency;

final class Main {
  public static void main(String[] args) throws ReflectiveOperationException {
    DirectDependency.run();
    var className = String.join(".", "reachbench", "dynamic", "DynamicDependency");
    Class.forName(className).getMethod("run").invoke(null);
  }
}
