/*
 *  Copyright 2022 Collate.
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

import { DatabaseSchema } from 'generated/entity/data/databaseSchema';
import { Dashboard } from '../../generated/entity/data/dashboard';
import { Mlmodel } from '../../generated/entity/data/mlmodel';
import { Pipeline } from '../../generated/entity/data/pipeline';
import { Table } from '../../generated/entity/data/table';
import { Topic } from '../../generated/entity/data/topic';

export type EntityData =
  | Table
  | Topic
  | Dashboard
  | Pipeline
  | Mlmodel
  | DatabaseSchema;

export interface Option {
  label: string;
  value: string;
  type: string;
  children?: string;
  'data-label'?: string;
  'data-testid'?: string;
  'data-usertype'?: string;
}

export interface TaskAction {
  label: string;
  key: string;
}

export enum TaskActionMode {
  VIEW = 'view',
  EDIT = 'edit',
}

export enum TaskTabs {
  CURRENT = 'current',
  DIFF = 'diff',
  NEW = 'new',
}
