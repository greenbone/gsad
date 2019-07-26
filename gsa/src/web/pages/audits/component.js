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

import {connect} from 'react-redux';

import _ from 'gmp/locale';

import Filter, {ALL_FILTER} from 'gmp/models/filter';

import {NO_VALUE, YES_VALUE} from 'gmp/parser';

import {map} from 'gmp/utils/array';
import {isDefined} from 'gmp/utils/identity';
import {hasId} from 'gmp/utils/id';

import withDownload from 'web/components/form/withDownload';
import {withRouter} from 'react-router-dom';

import {
  OPENVAS_DEFAULT_SCANNER_ID,
  OPENVAS_SCANNER_TYPE,
} from 'gmp/models/scanner';

import {
  loadEntities as loadAlerts,
  selector as alertSelector,
} from 'web/store/entities/alerts';

import {
  loadEntities as loadPolicies,
  selector as policiesSelector,
} from 'web/store/entities/policies';

import {
  loadEntities as loadSchedules,
  selector as scheduleSelector,
} from 'web/store/entities/schedules';

import {
  loadEntities as loadTargets,
  selector as targetSelector,
} from 'web/store/entities/targets';

import {
  loadAllEntities as loadReportFormats,
  selector as reportFormatsSelector,
} from 'web/store/entities/reportformats';

import {loadUserSettingDefaults} from 'web/store/usersettings/defaults/actions';
import {getUserSettingsDefaults} from 'web/store/usersettings/defaults/selectors';

import {getUsername} from 'web/store/usersettings/selectors';

import compose from 'web/utils/compose';
import PropTypes from 'web/utils/proptypes';
import withCapabilities from 'web/utils/withCapabilities';
import withGmp from 'web/utils/withGmp';
import {UNSET_VALUE, generateFilename} from 'web/utils/render';

import EntityComponent from 'web/entity/component';

import ScheduleComponent from 'web/pages/schedules/component';
import AlertComponent from 'web/pages/alerts/component';
import TargetComponent from 'web/pages/targets/component';

import AuditDialog from 'web/pages/audits/dialog';

// TODO: use id instead of name when a unique id becomes available
const REPORT_FORMATS_FILTER = Filter.fromString(
  'name="GCR PDF" and active=1 and trust=1 and rows=-1',
);

const DEFAULT_MIN_QOD = 70;

class AuditComponent extends React.Component {
  constructor(...args) {
    super(...args);

    this.state = {
      showDownloadReportDialog: false,
      auditDialogVisible: false,
      gcrFormatDefined: false,
    };

    const {gmp} = this.props;

    this.cmd = gmp.audit;

    this.handleAuditResume = this.handleAuditResume.bind(this);

    this.handleSaveAudit = this.handleSaveAudit.bind(this);

    this.handleAuditStart = this.handleAuditStart.bind(this);
    this.handleAuditStop = this.handleAuditStop.bind(this);

    this.handleReportDownloadClick = this.handleReportDownloadClick.bind(this);
    this.handleReportDownload = this.handleReportDownload.bind(this);

    this.openAuditDialog = this.openAuditDialog.bind(this);
    this.handleCloseAuditDialog = this.handleCloseAuditDialog.bind(this);

    this.handleAlertCreated = this.handleAlertCreated.bind(this);
    this.handleTargetCreated = this.handleTargetCreated.bind(this);
    this.handleScheduleCreated = this.handleScheduleCreated.bind(this);

    this.handleInteraction = this.handleInteraction.bind(this);

    this.handleChange = this.handleChange.bind(this);
  }

  componentDidMount() {
    this.props.loadUserSettingsDefaults();
    this.props.loadReportFormats().then(() => {
      const {reportFormats} = this.props;
      const gcrFormatDefined = isDefined(reportFormats[0]);
      this.setState({gcrFormatDefined});
    });
  }

  handleInteraction() {
    const {onInteraction} = this.props;
    if (isDefined(onInteraction)) {
      onInteraction();
    }
  }

  handleChange(value, name) {
    this.setState({[name]: value});
  }

  handleAuditStart(audit) {
    const {onStarted, onStartError} = this.props;

    this.handleInteraction();

    return this.cmd.start(audit).then(onStarted, onStartError);
  }

  handleAuditStop(audit) {
    const {onStopped, onStopError} = this.props;

    this.handleInteraction();

    return this.cmd.stop(audit).then(onStopped, onStopError);
  }

  handleAuditResume(audit) {
    const {onResumed, onResumeError} = this.props;

    this.handleInteraction();

    return this.cmd.resume(audit).then(onResumed, onResumeError);
  }

  handleAlertCreated(resp) {
    const {data} = resp;

    this.props.loadAlerts();

    this.setState(({alertIds}) => ({alertIds: [data.id, ...alertIds]}));
  }

  handleScheduleCreated(resp) {
    const {data} = resp;

    this.props.loadSchedules();

    this.setState({scheduleId: data.id});
  }

  handleTargetCreated(resp) {
    const {data} = resp;

    this.props.loadTargets();

    this.setState({targetId: data.id});
  }

  handleSaveAudit({
    alertIds,
    alterable,
    auto_delete,
    auto_delete_data,
    comment,
    policyId,
    hostsOrdering,
    id,
    in_assets,
    maxChecks,
    maxHosts,
    name,
    scheduleId,
    schedulePeriods,
    sourceIface,
    targetId,
    audit,
  }) {
    const {gmp} = this.props;

    let scannerId = OPENVAS_DEFAULT_SCANNER_ID;
    const scannerType = OPENVAS_SCANNER_TYPE;

    const tagId = undefined;
    const addTag = NO_VALUE;

    const applyOverrides = YES_VALUE;
    const minQod = DEFAULT_MIN_QOD;

    this.handleInteraction();

    if (isDefined(id)) {
      // save edit part
      if (isDefined(audit) && !audit.isChangeable()) {
        // arguments need to be undefined if the audit is not changeable
        targetId = undefined;
        scannerId = undefined;
        policyId = undefined;
      }
      const {onSaved, onSaveError} = this.props;
      return gmp.audit
        .save({
          alertIds,
          alterable,
          autoDelete: auto_delete,
          autoDeleteData: auto_delete_data,
          applyOverrides,
          comment,
          policyId,
          hostsOrdering,
          id,
          inAssets: in_assets,
          maxChecks,
          maxHosts,
          minQod,
          name,
          scannerId,
          scannerType,
          scheduleId,
          schedulePeriods,
          targetId,
          sourceIface,
        })
        .then(onSaved, onSaveError)
        .then(() => this.closeAuditDialog());
    }

    const {onCreated, onCreateError} = this.props;
    return gmp.audit
      .create({
        addTag,
        alertIds,
        alterable,
        applyOverrides,
        autoDelete: auto_delete,
        autoDeleteData: auto_delete_data,
        comment,
        policyId,
        hostsOrdering,
        inAssets: in_assets,
        maxChecks,
        maxHosts,
        minQod,
        name,
        scannerType,
        scannerId,
        scheduleId,
        schedulePeriods,
        sourceIface,
        tagId,
        targetId: targetId,
      })
      .then(onCreated, onCreateError)
      .then(() => this.closeAuditDialog());
  }

  closeAuditDialog() {
    this.setState({auditDialogVisible: false});
  }

  handleCloseAuditDialog() {
    this.closeAuditDialog();
    this.handleInteraction();
  }

  openAuditDialog(audit) {
    const {capabilities} = this.props;

    this.props.loadAlerts();
    this.props.loadPolicies();
    this.props.loadSchedules();
    this.props.loadTargets();

    if (isDefined(audit)) {
      const canAccessSchedules =
        capabilities.mayAccess('schedules') && isDefined(audit.schedule);
      const scheduleId = canAccessSchedules ? audit.schedule.id : UNSET_VALUE;
      const schedulePeriods = canAccessSchedules
        ? audit.schedule_periods
        : undefined;

      this.setState({
        auditDialogVisible: true,
        alertIds: map(audit.alerts, alert => alert.id),
        alterable: audit.alterable,
        applyOverrides: audit.apply_overrides,
        auto_delete: audit.auto_delete,
        auto_delete_data: audit.auto_delete_data,
        comment: audit.comment,
        policyId: hasId(audit.config) ? audit.config.id : undefined,
        hostsOrdering: audit.hosts_ordering,
        id: audit.id,
        in_assets: audit.in_assets,
        maxChecks: audit.max_checks,
        maxHosts: audit.max_hosts,
        minQod: audit.min_qod,
        name: audit.name,
        scannerId: hasId(audit.scanner) ? audit.scanner.id : undefined,
        scheduleId,
        schedulePeriods,
        sourceIface: audit.source_iface,
        targetId: hasId(audit.target) ? audit.target.id : undefined,
        audit,
        title: _('Edit Audit {{name}}', audit),
      });
    } else {
      const {
        defaultAlertId,
        defaultScannerId = OPENVAS_DEFAULT_SCANNER_ID,
        defaultScheduleId,
        defaultTargetId,
      } = this.props;

      const alertIds = isDefined(defaultAlertId) ? [defaultAlertId] : [];

      const defaultScannerType = OPENVAS_SCANNER_TYPE;

      this.setState({
        auditDialogVisible: true,
        alertIds,
        alterable: undefined,
        applyOverrides: undefined,
        auto_delete: undefined,
        auto_delete_data: undefined,
        comment: undefined,
        policyId: undefined,
        hostsOrdering: undefined,
        id: undefined,
        in_assets: undefined,
        maxChecks: undefined,
        maxHosts: undefined,
        minQod: undefined,
        name: undefined,
        scannerId: defaultScannerId,
        scanner_type: defaultScannerType,
        scheduleId: defaultScheduleId,
        schedulePeriods: undefined,
        sourceIface: undefined,
        targetId: defaultTargetId,
        audit: undefined,
        title: _('New Audit'),
      });
    }
    this.handleInteraction();
  }

  handleReportDownloadClick(audit) {
    this.setState({
      audit,
    });

    this.handleReportDownload(audit);
  }

  handleReportDownload(audit) {
    const {
      gmp,
      reportExportFileName,
      username,
      reportFormats = [],
      onDownload,
    } = this.props;

    const [reportFormat] = reportFormats;

    const extension = isDefined(reportFormat)
      ? reportFormat.extension
      : 'unknown'; // unknown should never happen but we should be save here

    this.handleInteraction();

    const {id} = audit.last_report;

    gmp.report
      .download(
        {id},
        {
          reportFormatId: reportFormat.id,
          deltaReportId: undefined,
          filter: undefined,
        },
      )
      .then(response => {
        const {data} = response;
        const filename = generateFilename({
          extension,
          fileNameFormat: reportExportFileName,
          id: id,
          reportFormat: reportFormat.name,
          resourceName: audit.name,
          resourceType: 'report',
          username,
        });
        onDownload({filename, data});
      }, this.handleError);
  }

  render() {
    const {
      alerts,
      policies,
      schedules,
      targets,
      children,
      onCloned,
      onCloneError,
      onCreated,
      onCreateError,
      onDeleted,
      onDeleteError,
      onDownloaded,
      onDownloadError,
      onInteraction,
    } = this.props;

    const {
      alertIds,
      alterable,
      auto_delete,
      auto_delete_data,
      policyId,
      comment,
      hostsOrdering,
      id,
      in_assets,
      gcrFormatDefined,
      maxChecks,
      maxHosts,
      name,
      scheduleId,
      schedulePeriods,
      sourceIface,
      targetId,
      audit,
      auditDialogVisible,
      title = _('Edit Audit {{name}}', audit),
    } = this.state;
    return (
      <React.Fragment>
        <EntityComponent
          name="audit"
          onCreated={onCreated}
          onCreateError={onCreateError}
          onCloned={onCloned}
          onCloneError={onCloneError}
          onDeleted={onDeleted}
          onDeleteError={onDeleteError}
          onDownloaded={onDownloaded}
          onDownloadError={onDownloadError}
          onInteraction={onInteraction}
        >
          {other => (
            <React.Fragment>
              {children({
                ...other,
                create: this.openAuditDialog,
                edit: this.openAuditDialog,
                start: this.handleAuditStart,
                stop: this.handleAuditStop,
                resume: this.handleAuditResume,
                reportDownload: this.handleReportDownloadClick,
                gcrFormatDefined: gcrFormatDefined,
              })}

              {auditDialogVisible && (
                <TargetComponent
                  onCreated={this.handleTargetCreated}
                  onInteraction={onInteraction}
                >
                  {({create: createtarget}) => (
                    <AlertComponent
                      onCreated={this.handleAlertCreated}
                      onInteraction={onInteraction}
                    >
                      {({create: createalert}) => (
                        <ScheduleComponent
                          onCreated={this.handleScheduleCreated}
                          onInteraction={onInteraction}
                        >
                          {({create: createschedule}) => (
                            <AuditDialog
                              alerts={alerts}
                              alertIds={alertIds}
                              alterable={alterable}
                              auto_delete={auto_delete}
                              auto_delete_data={auto_delete_data}
                              comment={comment}
                              policyId={policyId}
                              hostsOrdering={hostsOrdering}
                              id={id}
                              in_assets={in_assets}
                              maxChecks={maxChecks}
                              maxHosts={maxHosts}
                              name={name}
                              policies={policies}
                              scheduleId={scheduleId}
                              schedulePeriods={schedulePeriods}
                              schedules={schedules}
                              sourceIface={sourceIface}
                              targetId={targetId}
                              targets={targets}
                              audit={audit}
                              title={title}
                              onNewAlertClick={createalert}
                              onNewTargetClick={createtarget}
                              onNewScheduleClick={createschedule}
                              onChange={this.handleChange}
                              onClose={this.handleCloseAuditDialog}
                              onSave={this.handleSaveAudit}
                            />
                          )}
                        </ScheduleComponent>
                      )}
                    </AlertComponent>
                  )}
                </TargetComponent>
              )}
            </React.Fragment>
          )}
        </EntityComponent>
      </React.Fragment>
    );
  }
}

AuditComponent.propTypes = {
  alerts: PropTypes.arrayOf(PropTypes.model),
  capabilities: PropTypes.capabilities.isRequired,
  children: PropTypes.func.isRequired,
  defaultAlertId: PropTypes.id,
  defaultScannerId: PropTypes.id,
  defaultScheduleId: PropTypes.id,
  defaultTargetId: PropTypes.id,
  gmp: PropTypes.gmp.isRequired,
  loadAlerts: PropTypes.func.isRequired,
  loadPolicies: PropTypes.func.isRequired,
  loadReportFormats: PropTypes.func.isRequired,
  loadSchedules: PropTypes.func.isRequired,
  loadTargets: PropTypes.func.isRequired,
  loadUserSettingsDefaults: PropTypes.func.isRequired,
  policies: PropTypes.arrayOf(PropTypes.model),
  reportExportFileName: PropTypes.object,
  reportFormats: PropTypes.array,
  schedules: PropTypes.arrayOf(PropTypes.model),
  targets: PropTypes.arrayOf(PropTypes.model),
  username: PropTypes.string,
  onCloneError: PropTypes.func,
  onCloned: PropTypes.func,
  onCreateError: PropTypes.func,
  onCreated: PropTypes.func,
  onDeleteError: PropTypes.func,
  onDeleted: PropTypes.func,
  onDownload: PropTypes.func.isRequired,
  onDownloadError: PropTypes.func,
  onDownloaded: PropTypes.func,
  onInteraction: PropTypes.func.isRequired,
  onResumeError: PropTypes.func,
  onResumed: PropTypes.func,
  onSaveError: PropTypes.func,
  onSaved: PropTypes.func,
  onStartError: PropTypes.func,
  onStarted: PropTypes.func,
  onStopError: PropTypes.func,
  onStopped: PropTypes.func,
};

const mapStateToProps = (rootState, {match}) => {
  const alertSel = alertSelector(rootState);
  const userDefaults = getUserSettingsDefaults(rootState);
  const policiesSel = policiesSelector(rootState);
  const scheduleSel = scheduleSelector(rootState);
  const targetSel = targetSelector(rootState);
  const userDefaultsSelector = getUserSettingsDefaults(rootState);
  const username = getUsername(rootState);

  const reportFormatsSel = reportFormatsSelector(rootState);

  return {
    alerts: alertSel.getEntities(ALL_FILTER),
    defaultAlertId: userDefaults.getValueByName('defaultalert'),
    defaultScheduleId: userDefaults.getValueByName('defaultschedule'),
    defaultTargetId: userDefaults.getValueByName('defaulttarget'),
    reportExportFileName: userDefaultsSelector.getValueByName(
      'reportexportfilename',
    ),
    reportFormats: reportFormatsSel.getAllEntities(REPORT_FORMATS_FILTER),
    policies: policiesSel.getEntities(ALL_FILTER),
    schedules: scheduleSel.getEntities(ALL_FILTER),
    targets: targetSel.getEntities(ALL_FILTER),
    username,
  };
};

const mapDispatchToProp = (dispatch, {gmp}) => ({
  loadAlerts: () => dispatch(loadAlerts(gmp)(ALL_FILTER)),
  loadPolicies: () => dispatch(loadPolicies(gmp)(ALL_FILTER)),
  loadSchedules: () => dispatch(loadSchedules(gmp)(ALL_FILTER)),
  loadTargets: () => dispatch(loadTargets(gmp)(ALL_FILTER)),
  loadUserSettingsDefaults: () => dispatch(loadUserSettingDefaults(gmp)()),
  loadReportFormats: () =>
    dispatch(loadReportFormats(gmp)(REPORT_FORMATS_FILTER)),
});

export default compose(
  withGmp,
  withCapabilities,
  withDownload,
  withRouter,
  connect(
    mapStateToProps,
    mapDispatchToProp,
  ),
)(AuditComponent);
