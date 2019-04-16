/* Copyright (C) 2019 Greenbone Networks GmbH
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
import {storiesOf} from '@storybook/react';
import RadioComponent from '../web/components/form/radio';

class TestRadio extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      notification: '',
      value: '',
    };
    this.handleChange = this.handleChange.bind(this);
  }

  handleChange(value, name) {
    this.setState({
      value,
    });
  }

  render() {
    const text = 'You chose ' + this.state.value;
    return (
      <div>
        <ul>
          <li>
            Coffee
            <RadioComponent
              name="radio1"
              value="coffee"
              onChange={this.handleChange}
            />
          </li>
          <li>
            Tea
            <RadioComponent
              name="radio1"
              value="tea"
              onChange={this.handleChange}
            />
          </li>
          <li>
            Water
            <RadioComponent
              name="radio1"
              value="water"
              onChange={this.handleChange}
            />
          </li>
          <h3>{text}</h3>
        </ul>
      </div>
    );
  }
}

storiesOf('Radio', module)
  .add('default', () => <RadioComponent />)
  .add('checked', () => <RadioComponent defaultChecked="true" />)
  .add('disabled', () => <RadioComponent disabled={true} />)
  .add('multiple options', () => (
    <div>
      <ul>
        <li>
          Coffee
          <RadioComponent name="radio1" />
        </li>
        <li>
          Tea
          <RadioComponent name="radio1" />
        </li>
        <li>
          Water
          <RadioComponent name="radio1" />
        </li>
      </ul>
    </div>
  ))
  .add('with change event', () => <TestRadio />);
