# -*- coding: utf-8 -*-
from django.contrib.contenttypes.models import ContentType

from labels.models import LabeledResource

from ..base.entries import BaseEntry

__all__ = [
    'AccountEntry', 'AccountTemplateEntry',
    'HistoricalAccountEntry', 'PersonalAssetCredentialEntry',
]

LABEL_SAFE = 'cyberark_safe'
LABEL_FOLDER = 'cyberark_folder'
LABEL_APP_ID = 'cyberark_app_id'
LABEL_QUERY = 'cyberark_query'


def load_labels(instance):
    """Return `(instance_labels, asset_labels)` with a single query.

    Labels are the only place where the CyberArk location is stored, so the
    account labels take precedence over the asset labels.
    """
    asset = getattr(instance, 'asset', None)
    targets = [instance]
    if asset is not None:
        targets.append(asset)

    content_types = {
        obj._meta.model: ContentType.objects.get_for_model(obj._meta.model)
        for obj in targets
    }
    rows = LabeledResource.objects.filter(
        res_type_id__in=[ct.id for ct in content_types.values()],
        res_id__in=[str(obj.pk) for obj in targets],
    ).values_list('res_type_id', 'res_id', 'label__name', 'label__value')

    labels = {}
    for res_type_id, res_id, name, value in rows:
        labels.setdefault((res_type_id, str(res_id)), {})[name] = value

    instance_labels = labels.get(
        (content_types[instance._meta.model].id, str(instance.pk)), {}
    )
    asset_labels = {}
    if asset is not None:
        asset_labels = labels.get(
            (content_types[asset._meta.model].id, str(asset.pk)), {}
        )
    return instance_labels, asset_labels


class CyberArkEntry(BaseEntry):
    """CyberArk resolves secrets by attributes, so there is no KV path."""

    # Duck-typed capability flag instead of an isinstance() check: the module
    # can be imported under two prefixes (accounts.* / apps.accounts.*), which
    # produces distinct class objects for the same file.
    ccp_capable = False

    @property
    def path_spec(self):
        return f'{self.instance._meta.model_name}/{self.instance.pk}'


class AccountEntry(CyberArkEntry):
    ccp_capable = True

    @property
    def ccp_values(self):
        account = self.instance
        asset = getattr(account, 'asset', None)
        account_labels, asset_labels = load_labels(account)

        def pick(name):
            return account_labels.get(name) or asset_labels.get(name) or ''

        return {
            'safe': pick(LABEL_SAFE),
            'folder': pick(LABEL_FOLDER),
            'app_id': pick(LABEL_APP_ID),
            'username': account.username or '',
            'address': getattr(asset, 'address', '') or '',
            'asset_name': getattr(asset, 'name', '') or '',
            'account_name': account.name or '',
            'extra': pick(LABEL_QUERY),
        }


class AccountTemplateEntry(CyberArkEntry):
    pass


class HistoricalAccountEntry(CyberArkEntry):
    pass


class PersonalAssetCredentialEntry(CyberArkEntry):
    pass
