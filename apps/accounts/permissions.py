from django.utils.translation import gettext_lazy as _
from rest_framework import permissions

from common.utils import get_object_or_none


def check_permissions(request):
    act = request.data.get('action')
    if act == 'push':
        code = 'accounts.push_account'
    elif act == 'remove':
        code = 'accounts.remove_account'
    else:
        code = 'accounts.verify_account'
    return request.user.has_perm(code)


class AccountTaskActionPermission(permissions.IsAuthenticated):

    def has_permission(self, request, view):
        return super().has_permission(request, view) \
            and check_permissions(request)


class IsPermedAccountSecret(permissions.BasePermission):
    """
    校验用户是否有权限查看账号密码：

    1. 拥有 RBAC 权限 `accounts.view_accountsecret` 的用户（管理员）可以查看；
    2. 通过授权规则获得该账号 `view_secret` 动作的用户可以在工作台查看；
    其他情况一律拒绝。
    """
    message = _('No permission to view account secret')

    def has_permission(self, request, view):
        if request.user.has_perm('accounts.view_accountsecret'):
            return True

        # OPTIONS/schema 探测直接放行
        if view.action == 'metadata':
            return True

        # 非管理员只能查看单个账号的密码，不允许批量导出
        if view.action != 'retrieve':
            return False

        account = self.get_account(view)
        if not account:
            return False
        return self.has_view_secret_perm(request.user, account)

    @staticmethod
    def get_account(view):
        from accounts.models import Account

        pk = view.kwargs.get('pk')
        if not pk:
            return None
        return get_object_or_none(Account, pk=pk)

    @staticmethod
    def has_view_secret_perm(user, account):
        from perms.const import ActionChoices
        from perms.utils import PermAssetDetailUtil

        try:
            util = PermAssetDetailUtil(user, account.asset_id)
            return util.check_perm_actions(
                account.username, [ActionChoices.view_secret.value]
            )
        except Exception:
            return False
