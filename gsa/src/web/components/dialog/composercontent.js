/* Copyright (C) 2018 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

import React from 'react';

import styled from 'styled-components';

import _ from 'gmp/locale';

import {NO_VALUE, YES_VALUE, parseYesNo} from 'gmp/parser';

import PropTypes from 'web/utils/proptypes';

import CheckBox from 'web/components/form/checkbox';
import FormGroup from 'web/components/form/formgroup';
import Radio from 'web/components/form/radio';

import Divider from 'web/components/layout/divider';
import Layout from 'web/components/layout/layout';

import Theme from 'web/utils/theme';

export const COMPOSER_CONTENT_DEFAULTS = {
  applyOverrides: NO_VALUE,
  includeNotes: YES_VALUE,
  includeOverrides: YES_VALUE,
};

const FilterField = styled.div`
  display: block;
  height: 22px;
  color: ${Theme.darkGray};
  border: 1px solid ${Theme.inputBorderGray};
  border-radius: 2px;
  padding: 3px 8px;
  cursor: not-allowed;
  background-color: ${Theme.dialogGray};
  width: 100%;
`;

const ComposerContent = ({
  applyOverrides,
  filterString,
  includeNotes,
  includeOverrides,
  onValueChange,
}) => (
  <Layout flex="column">
    <FormGroup title={_('Applied Filter')} titleSize="3">
      <FilterField
        title={_('To change the filter, please filter your results on the ' +
          'report page.')}
      >
        {filterString}
      </FilterField>
    </FormGroup>
    <FormGroup title={_('Severity')} titleSize="3">
      <Divider>
        <Radio
          name="applyOverrides"
          value={NO_VALUE}
          checked={!parseYesNo(applyOverrides)}
          title={_('Original severity')}
          onChange={onValueChange}
        />
        <Radio
          name="applyOverrides"
          value={YES_VALUE}
          checked={parseYesNo(applyOverrides)}
          title={_('With overrides applied')}
          onChange={onValueChange}
        />
      </Divider>
    </FormGroup>
    <FormGroup title={_('Include')} titleSize="3">
      <Divider>
        <CheckBox
          data-testid="includeNotes"
          name="includeNotes"
          checked={includeNotes}
          checkedValue={YES_VALUE}
          unCheckedValue={NO_VALUE}
          title={_('Notes')}
          onChange={onValueChange}
        />
        <CheckBox
          name="includeOverrides"
          checked={includeOverrides}
          checkedValue={YES_VALUE}
          unCheckedValue={NO_VALUE}
          title={_('Overrides')}
          onChange={onValueChange}
        />
      </Divider>
    </FormGroup>
  </Layout>
);


ComposerContent.propTypes = {
  applyOverrides: PropTypes.numberOrNumberString.isRequired,
  filterString: PropTypes.string.isRequired,
  includeNotes: PropTypes.number.isRequired,
  includeOverrides: PropTypes.number.isRequired,
  onValueChange: PropTypes.func.isRequired,
};

export default ComposerContent;

// vim: set ts=2 sw=2 tw=80: