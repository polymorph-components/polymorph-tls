// Host-side JS implementation of polymorph:test/test-context@0.1.0.
// The jco analog of the context provider component: the runner is the
// provider (webcrypto-pattern host-implemented imports).
export class Context {
  constructor(onDiagnostic) {
    this.onDiagnostic = onDiagnostic;
  }
  async diagnostic(msg) {
    this.onDiagnostic(msg);
  }
}
