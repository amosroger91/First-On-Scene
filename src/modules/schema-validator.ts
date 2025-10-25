/**
 * Schema Validation Module
 * Validates collected forensic artifacts against the JSON schema
 */

import Ajv, { JSONSchemaType, ValidateFunction } from 'ajv';
import * as fs from 'fs';
import * as path from 'path';
import { CollectionOutput } from '../types';

export class SchemaValidator {
  private ajv: Ajv;
  private validator: ValidateFunction<CollectionOutput> | null = null;

  constructor() {
    this.ajv = new Ajv({ allErrors: true, strict: false });
  }

  /**
   * Load and compile the artifact schema
   * @param schemaPath Path to the artifact_schema.json file
   */
  loadSchema(schemaPath: string): void {
    if (!fs.existsSync(schemaPath)) {
      throw new Error(`Schema file not found: ${schemaPath}`);
    }

    const schemaContent = fs.readFileSync(schemaPath, 'utf-8');
    const schema = JSON.parse(schemaContent) as JSONSchemaType<CollectionOutput>;

    this.validator = this.ajv.compile(schema);
  }

  /**
   * Validate collected artifact data against the schema
   * @param data The parsed JSON data from native script output
   * @returns true if valid, false otherwise
   * @throws Error with validation details if invalid
   */
  validate(data: unknown): data is CollectionOutput {
    if (!this.validator) {
      throw new Error('Schema not loaded. Call loadSchema() first.');
    }

    const valid = this.validator(data);

    if (!valid) {
      const errors = this.validator.errors || [];
      const errorMessages = errors.map(err =>
        `${err.instancePath || 'root'}: ${err.message || 'validation failed'}`
      ).join('\n');

      throw new Error(`Schema validation failed:\n${errorMessages}`);
    }

    return true;
  }

  /**
   * Validate and return typed artifact data
   * @param data Raw data to validate
   * @returns Validated and typed CollectionOutput
   */
  validateAndParse(data: unknown): CollectionOutput {
    if (this.validate(data)) {
      return data as CollectionOutput;
    }
    throw new Error('Validation failed');
  }

  /**
   * Get human-readable validation errors
   * @returns Array of error messages
   */
  getLastErrors(): string[] {
    if (!this.validator || !this.validator.errors) {
      return [];
    }

    return this.validator.errors.map(err =>
      `Field: ${err.instancePath || 'root'} - ${err.message || 'unknown error'}`
    );
  }
}

/**
 * Convenience function to validate artifact data
 * @param data Data to validate
 * @param rootDir Root directory of the application (to locate schema)
 * @returns Validated CollectionOutput
 */
export function validateArtifacts(data: unknown, rootDir: string): CollectionOutput {
  const validator = new SchemaValidator();
  const schemaPath = path.join(rootDir, 'schemas', 'artifact_schema.json');

  validator.loadSchema(schemaPath);
  return validator.validateAndParse(data);
}
