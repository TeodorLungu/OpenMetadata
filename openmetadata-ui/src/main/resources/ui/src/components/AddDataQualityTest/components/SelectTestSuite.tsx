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

import {
  Button,
  Divider,
  Form,
  FormProps,
  Input,
  Row,
  Select,
  Space,
  Typography,
} from 'antd';
import { useForm } from 'antd/lib/form/Form';
import { AxiosError } from 'axios';
import { t } from 'i18next';
import { isEmpty } from 'lodash';
import React, { useEffect, useRef, useState } from 'react';
import { useHistory, useParams } from 'react-router-dom';
import { getListTestSuites } from 'rest/testAPI';
import {
  API_RES_MAX_SIZE,
  getTableTabPath,
} from '../../../constants/constants';
import { TestSuite } from '../../../generated/tests/testSuite';
import { useAuth } from '../../../hooks/authHooks';
import SVGIcons, { Icons } from '../../../utils/SvgUtils';
import { showErrorToast } from '../../../utils/ToastUtils';
import { useAuthContext } from '../../authentication/auth-provider/AuthProvider';
import RichTextEditor from '../../common/rich-text-editor/RichTextEditor';
import { EditorContentRef } from '../../common/rich-text-editor/RichTextEditor.interface';
import {
  SelectTestSuiteProps,
  SelectTestSuiteType,
} from '../AddDataQualityTest.interface';

const SelectTestSuite: React.FC<SelectTestSuiteProps> = ({
  onSubmit,
  initialValue,
}) => {
  const { entityTypeFQN } = useParams<Record<string, string>>();
  const { isAdminUser } = useAuth();
  const { isAuthDisabled } = useAuthContext();
  const [form] = useForm();
  const hasAccess = isAdminUser || isAuthDisabled;
  const history = useHistory();
  const [formData, setFormData] = useState<{
    testSuiteId: string;
    testSuiteName: string;
  }>({
    testSuiteId: initialValue?.data?.id || '',
    testSuiteName: initialValue?.name || '',
  });
  const [isNewTestSuite, setIsNewTestSuite] = useState(
    initialValue?.isNewTestSuite ?? false
  );
  const [testSuites, setTestSuites] = useState<TestSuite[]>([]);
  const markdownRef = useRef<EditorContentRef>();

  const fetchAllTestSuite = async () => {
    try {
      const { data } = await getListTestSuites({
        limit: API_RES_MAX_SIZE,
      });

      setTestSuites(data);
    } catch (error) {
      showErrorToast(error as AxiosError);
    }
  };

  const getDescription = () => {
    return markdownRef.current?.getEditorContent() || '';
  };

  const resetSelectedId = () => {
    form.setFieldsValue({ testSuiteId: undefined });
  };

  const handleCancelClick = () => {
    history.push(getTableTabPath(entityTypeFQN, 'profiler'));
  };

  const handleFormSubmit: FormProps['onFinish'] = (value) => {
    const data: SelectTestSuiteType = {
      name: value.testSuiteName,
      description: getDescription(),
      data: testSuites.find((suite) => suite.id === value.testSuiteId),
      isNewTestSuite: isEmpty(formData.testSuiteId),
    };

    onSubmit(data);
  };

  useEffect(() => {
    if (testSuites.length === 0) {
      fetchAllTestSuite();
    }
  }, []);

  return (
    <Form
      form={form}
      initialValues={{
        testSuiteId: initialValue?.data?.id,
        testSuiteName: initialValue?.name,
      }}
      layout="vertical"
      name="selectTestSuite"
      onFinish={handleFormSubmit}
      onValuesChange={(value, values) => {
        setFormData(values);
        if (value.testSuiteId) {
          markdownRef?.current?.clearEditorContent();
          form.setFieldsValue({
            ...values,
            testSuiteName: '',
          });
        } else if (value.testSuiteName) {
          resetSelectedId();
        }
      }}>
      <Form.Item
        label={`${t('label.test-suite')}:`}
        name="testSuiteId"
        rules={[
          {
            required:
              !isNewTestSuite || !isEmpty(form.getFieldValue('testSuiteId')),
            message: `${t('message.field-text-is-required', {
              fieldText: t('label.test-suite'),
            })}`,
          },
        ]}>
        <Select
          options={testSuites.map((suite) => ({
            label: suite.name,
            value: suite.id,
          }))}
          placeholder={t('label.select-field', {
            field: t('label.test-suite'),
          })}
        />
      </Form.Item>
      {hasAccess && (
        <>
          <Divider plain>OR</Divider>

          {isNewTestSuite ? (
            <>
              <Typography.Paragraph
                className="text-base m-t-lg"
                data-testid="new-test-title">
                {t('label.new-test-suite')}
              </Typography.Paragraph>
              <Form.Item
                label={`${t('label.name')}:`}
                name="testSuiteName"
                rules={[
                  {
                    required: isEmpty(form.getFieldValue('testSuiteId')),
                    message: `${t('message.field-text-is-required', {
                      fieldText: t('label.name'),
                    })}`,
                  },
                  {
                    pattern: /^[A-Za-z0-9_]*$/g,
                    message: t('message.special-character-not-allowed'),
                  },
                  {
                    validator: (_, value) => {
                      if (testSuites.some((suite) => suite.name === value)) {
                        return Promise.reject(
                          t('message.entity-already-exists', {
                            entity: t('label.name'),
                          })
                        );
                      }

                      return Promise.resolve();
                    },
                  },
                ]}>
                <Input
                  data-testid="test-suite-name"
                  placeholder={t('message.enter-test-suite-name')}
                />
              </Form.Item>
              <Form.Item
                label={`${t('label.description')}:`}
                name="description"
                rules={[
                  {
                    required: isEmpty(form.getFieldValue('testSuiteId')),
                    validator: () => {
                      if (
                        isEmpty(getDescription()) &&
                        isEmpty(form.getFieldValue('testSuiteId'))
                      ) {
                        return Promise.reject(
                          `${t('message.field-text-is-required', {
                            fieldText: t('label.description'),
                          })}`
                        );
                      }

                      return Promise.resolve();
                    },
                  },
                ]}>
                <RichTextEditor
                  initialValue={initialValue?.description || ''}
                  ref={markdownRef}
                  style={{
                    margin: 0,
                  }}
                  onTextChange={() => {
                    resetSelectedId();
                  }}
                />
              </Form.Item>
            </>
          ) : (
            <Row className="m-b-xlg" justify="center">
              <Button
                data-testid="create-new-test-suite"
                icon={
                  <SVGIcons
                    alt="plus"
                    className="w-4 m-r-xss"
                    icon={Icons.ICON_PLUS_PRIMARY}
                  />
                }
                onClick={() => setIsNewTestSuite(true)}>
                <span className="tw-text-primary">
                  {t('label.create-new-test-suite')}
                </span>
              </Button>
            </Row>
          )}
        </>
      )}

      <Form.Item noStyle>
        <Space className="tw-w-full tw-justify-end" size={16}>
          <Button onClick={handleCancelClick}>{t('label.cancel')}</Button>
          <Button data-testid="next-button" htmlType="submit" type="primary">
            {t('label.next')}
          </Button>
        </Space>
      </Form.Item>
    </Form>
  );
};

export default SelectTestSuite;
