/**
 * Base API class
 * All API services should extend this class
 */
export abstract class BaseApi {
  protected basePath: string;

  constructor(basePath: string) {
    this.basePath = basePath;
  }

  /**
   * Build URL with base path
   */
  protected url(path: string = ''): string {
    return `${this.basePath}${path}`;
  }
}
