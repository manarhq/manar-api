import 'reflect-metadata';
import { CliModule } from './cli/cli.module';
import { runCli } from './cli/run-cli';

void runCli(CliModule);
