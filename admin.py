from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from auth import admin_required

# Define breadcrumb mapping
BREADCRUMBS_MAP = {
    'admin.choice': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'}
    ],
    'admin.dashboard': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Dashboard', 'endpoint': 'admin.dashboard'}
    ],
    'admin.manage_policies': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Policies', 'endpoint': 'admin.manage_policies'}
    ],
    'admin.create_policy': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Policies', 'endpoint': 'admin.manage_policies'},
        {'text': 'Create Policy', 'endpoint': 'admin.create_policy'}
    ],
    'admin.manage_single_policy': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Policies', 'endpoint': 'admin.manage_policies'},
        {'text': 'Manage Policy', 'endpoint': 'admin.manage_single_policy'}
    ],
    'admin.manage_single_policy': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Policies', 'endpoint': 'admin.manage_policies'},
        {'text': 'Manage Policy', 'endpoint': 'admin.manage_single_policy'}
    ],
    'admin.manage_single_policy': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Policies', 'endpoint': 'admin.manage_policies'},
        {'text': 'Manage Policy', 'endpoint': 'admin.manage_single_policy'}
    ],
    'admin.delete_policy': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Policies', 'endpoint': 'admin.manage_policies'},
        {'text': 'Delete Policy', 'endpoint': 'admin.delete_policy'}
    ],
    'admin.manage_assignments': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Assignments', 'endpoint': 'admin.manage_assignments'}
    ],
    'admin.create_assignment': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Assignments', 'endpoint': 'admin.manage_assignments'},
        {'text': 'Create Assignment', 'endpoint': 'admin.create_assignment'}
    ],
    'admin.delete_assignment': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Assignments', 'endpoint': 'admin.manage_assignments'},
        {'text': 'Delete Assignment', 'endpoint': 'admin.delete_assignment'}
    ],
    'admin.manage_users': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Users', 'endpoint': 'admin.manage_users'}
    ],
    'admin.manage_single_user': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Users', 'endpoint': 'admin.manage_users'},
        {'text': 'Manage User', 'endpoint': 'admin.manage_single_user'}
    ],
    'admin.manage_all_users': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Users', 'endpoint': 'admin.manage_users'},
        {'text': 'Manage All Users', 'endpoint': 'admin.manage_all_users'}
    ],
    'admin.whitelist': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Users', 'endpoint': 'admin.manage_users'},
        {'text': 'Whitelist', 'endpoint': 'admin.whitelist'}
    ],
    'admin.view_logs_search': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'View Logs', 'endpoint': 'admin.view_logs_search'}
    ],
    'admin.view_user_logs': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'View Logs', 'endpoint': 'admin.view_logs_search'},
        {'text': 'User Logs', 'endpoint': 'admin.view_user_logs'}
    ],
    'admin.manage_tags': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Tags', 'endpoint': 'admin.manage_tags'}
    ],
    'admin.create_tag': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Tags', 'endpoint': 'admin.manage_tags'},
        {'text': 'Create Tag', 'endpoint': 'admin.create_tag'}
    ],
    'admin.manage_tag_policies': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Tags', 'endpoint': 'admin.manage_tags'},
        {'text': 'Manage Tag Policies', 'endpoint': 'admin.manage_tag_policies'}
    ],
    'admin.add_tag_policy': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Tags', 'endpoint': 'admin.manage_tags'},
        {'text': 'Manage Tag Policies', 'endpoint': 'admin.manage_tag_policies'},
        {'text': 'Add Tag Policy', 'endpoint': 'admin.add_tag_policy'}
    ],
    'admin.delete_tag_policy': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Tags', 'endpoint': 'admin.manage_tags'},
        {'text': 'Manage Tag Policies', 'endpoint': 'admin.manage_tag_policies'},
        {'text': 'Delete Tag Policy', 'endpoint': 'admin.delete_tag_policy'}
    ],
    'admin.confirm_tag_policy_assignment': [
        {'text': 'Admin Home', 'endpoint': 'admin.choice'},
        {'text': 'Manage Tags', 'endpoint': 'admin.manage_tags'},
        {'text': 'Confirm Policy Assignment', 'endpoint': 'admin.confirm_tag_policy_assignment'}
    ],
}

def get_breadcrumbs_for_current_page():
    endpoint = request.endpoint
    breadcrumbs_data = BREADCRUMBS_MAP.get(endpoint, [])
    
    # Convert endpoint names to URLs
    formatted_breadcrumbs = []
    for item in breadcrumbs_data:
        formatted_breadcrumbs.append({
            'text': item['text'],
            'url': url_for(item['endpoint'])
        })
    return formatted_breadcrumbs

from db import (
    create_policy as write_create_policy, 
    get_policies as read_get_policies, 
    edit_policy as write_edit_policy, 
    get_policy as read_get_policy, 
    delete_policy as write_delete_policy, 
    create_assignment as write_create_assignment, 
    get_pending_assignments as read_get_pending_assignments, 
    delete_assignment as write_delete_assignment, 
    get_users as read_get_users, 
    get_user as read_get_user,
    update_user_role as write_update_user_role,
    get_policies_with_assignment_count,
    get_all_pending_assignments_with_status,
    get_user_assignment_logs,
    create_tag as write_create_tag,
    get_tags as read_get_tags,
    get_tag as read_get_tag,
    delete_tag as write_delete_tag,
    update_tag_members as write_update_tag_members,
    add_user_to_tag as write_add_user_to_tag,
    remove_user_from_tag as write_remove_user_from_tag,
    get_users_by_tag as read_get_users_by_tag,
    get_tags_with_member_count,
    get_users_with_tags,
    add_to_whitelist as write_add_to_whitelist,
    remove_from_whitelist as write_remove_from_whitelist,
    get_whitelist as read_get_whitelist,
    create_tag_policy as write_create_tag_policy,
    get_tag_policies_with_details as read_get_tag_policies_with_details,
    delete_tag_policy as write_delete_tag_policy,
    get_policies as read_get_policies,
    get_user_assignments as get_user_assignments,
    get_assignments_by_policy
)
from datetime import datetime, date
from time import time

admin = Blueprint('admin', __name__, url_prefix='/admin')



@admin.route('/choice', methods=['GET'])
@admin_required
def choice():
    return render_template('admin/choice.html')

@admin.route('/dashboard', methods=['GET'])
@admin_required
def dashboard():
    # Get pending assignments with status
    pending_assignments_result = get_all_pending_assignments_with_status()
    pending_assignments = pending_assignments_result['data'] if pending_assignments_result['status'] == '200' else []
    
    return render_template('admin/dashboard.html', 
                         pending_assignments=pending_assignments,
                         now=int(time()))


@admin.route('/logs', methods=['GET'])
@admin_required
def view_logs_search():
    query = request.args.get('q', '')
    users_result = get_users_with_tags()
    users = users_result['data'] if users_result['status'] == '200' else []

    if query:
        users = [u for u in users if query.lower() in u['name'].lower()]

    return render_template('admin/view_logs_search.html',
                         users=users,
                         query=query)

@admin.route('/user/<user_uuid>/logs', methods=['GET'])
@admin_required
def view_user_logs(user_uuid):
    # Get user info
    user_result = read_get_user(uuid=user_uuid)
    if user_result['status'] != '200':
        flash('User not found.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    # Get user's assignment logs
    logs_result = get_user_assignment_logs(user_uuid)
    logs = logs_result['data'] if logs_result['status'] == '200' else []
    
    return render_template('admin/user_logs.html',
                         user_info=user_result['data'],
                         logs=logs)

@admin.route('/manage_tags', methods=['GET'])
@admin_required
def manage_tags():
    tags_result = get_tags_with_member_count()
    tags = tags_result['data'] if tags_result['status'] == '200' else []
    return render_template('admin/manage_tags/hub.html', tags=tags)

@admin.route('/manage_tags/create', methods=['GET', 'POST'])
@admin_required
def create_tag():
    if request.method == 'POST':
        name = request.form['name'].strip()
        description = request.form.get('description', '').strip()
        
        result = write_create_tag(name, description)
        if result['status'] == '201':
            flash(f'Tag "{name}" created successfully!', 'success')
            return redirect(url_for('admin.manage_tag_members', tag_uuid=result['data']['uuid']))
        else:
            flash(f'Failed to create tag: {result["message"]}', 'error')
        
        return redirect(url_for('admin.manage_tags'))
    
    return render_template('admin/manage_tags/create.html')

@admin.route('/manage_tags/<tag_uuid>/members', methods=['GET', 'POST'])
@admin_required
def manage_tag_members(tag_uuid):
    # Get tag info
    tag_result = read_get_tag(uuid=tag_uuid)
    if tag_result['status'] != '200':
        flash('Tag not found.', 'error')
        return redirect(url_for('admin.manage_tags'))
    
    tag_info = tag_result['data']
    
    if request.method == 'POST':
        # Get current members
        current_members = set(tag_info['members'].split(',')) if tag_info['members'] else set()
        
        # Get selected users
        selected_users = set(request.form.getlist('users'))
        
        # Determine which users to add and remove
        users_to_add = selected_users - current_members
        users_to_remove = current_members - selected_users
        
        # Process additions
        for user_uuid in users_to_add:
            write_add_user_to_tag(tag_uuid, user_uuid)
        
        # Process removals
        for user_uuid in users_to_remove:
            write_remove_user_from_tag(tag_uuid, user_uuid)
        
        flash(f'Tag membership updated successfully!', 'success')
        
        if users_to_add:
            # Store newly added users and tag_uuid in session to pass to confirmation page
            session['newly_added_users'] = list(users_to_add)
            session['current_tag_uuid'] = tag_uuid
            return redirect(url_for('admin.confirm_tag_policy_assignment'))
        else:
            return redirect(url_for('admin.manage_tags'))
    
    # Get all users with membership status
    all_users_result = read_get_users()
    if all_users_result['status'] != '200':
        flash('Could not retrieve users.', 'error')
        return redirect(url_for('admin.manage_tags'))
    
    current_members = set(tag_info['members'].split(',')) if tag_info['members'] else set()
    
    users = []
    for user in all_users_result['data']:
        user_dict = dict(user)
        user_dict['is_member'] = user['uuid'] in current_members
        users.append(user_dict)
    
    return render_template('admin/manage_tags/manage_members.html',
                         tag_info=tag_info,
                         users=users)

@admin.route('/manage_tags/edit', methods=['GET', 'POST'])
@admin_required
def edit_tag():
    if request.method == 'POST':
        tag_uuid = request.form['tag']
        new_name = request.form.get('name', '').strip()
        new_description = request.form.get('description', '').strip()
        
        # Get current tag data
        tag_result = read_get_tag(uuid=tag_uuid)
        if tag_result['status'] != '200':
            flash('Tag not found.', 'error')
            return redirect(url_for('admin.manage_tags'))
        
        current_tag = tag_result['data']
        
        # Use new values or keep current ones
        final_name = new_name if new_name else current_tag['name']
        final_description = new_description if new_description else current_tag['description']
        
        result = write_update_tag_members(tag_uuid, name=final_name, description=final_description)
        if result['status'] == '200':
            flash('Tag updated successfully!', 'success')
        else:
            flash(f'Failed to update tag: {result["message"]}', 'error')
        
        return redirect(url_for('admin.manage_tags'))
    
    tags_result = get_tags_with_member_count()
    tags = tags_result['data'] if tags_result['status'] == '200' else []
    return render_template('admin/manage_tags/edit.html', tags=tags)

@admin.route('/manage_tags/delete', methods=['POST'])
@admin_required
def delete_tag():
    tag_uuid = request.form.get('tag_uuid')
    if tag_uuid:
        result = write_delete_tag(tag_uuid)
        if result['status'] == '200':
            flash('Tag deleted successfully!', 'success')
        else:
            flash(f'Failed to delete tag: {result["message"]}', 'error')
    else:
        flash('No tag specified for deletion.', 'error')
    return redirect(url_for('admin.manage_tags'))

@admin.route('/manage_tags/<tag_uuid>/policies', methods=['GET'])
@admin_required
def manage_tag_policies(tag_uuid):
    tag_result = read_get_tag(uuid=tag_uuid)
    if tag_result['status'] != '200':
        flash('Tag not found.', 'error')
        return redirect(url_for('admin.manage_tags'))
    tag_info = tag_result['data']

    tag_policies_result = read_get_tag_policies_with_details(tag_uuid)
    tag_policies = tag_policies_result['data'] if tag_policies_result['status'] == '200' else []

    return render_template('admin/manage_tags/manage_policies.html',
                           tag_info=tag_info,
                           tag_policies=tag_policies)

@admin.route('/manage_tags/<tag_uuid>/policies/add', methods=['GET', 'POST'])
@admin_required
def add_tag_policy(tag_uuid):
    tag_result = read_get_tag(uuid=tag_uuid)
    if tag_result['status'] != '200':
        flash('Tag not found.', 'error')
        return redirect(url_for('admin.manage_tags'))
    tag_info = tag_result['data']

    if request.method == 'POST':
        policy_uuid = request.form['policy_uuid']
        due_date_str = request.form['due_date']
        due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
        today = date.today()
        timeframe_days = (due_date - today).days
        result = write_create_tag_policy(tag_uuid, policy_uuid, due_date)
        if result['status'] == '201':
            flash('''Policy linked to tag successfully!''', 'success')
        else:
            flash(f'Failed to link policy: {result["message"]}', 'error')
        return redirect(url_for('admin.manage_tag_policies', tag_uuid=tag_uuid))

    policies_result = read_get_policies()
    policies = policies_result['data'] if policies_result['status'] == '200' else []

    # Filter out policies already linked to this tag
    linked_policies_result = read_get_tag_policies_with_details(tag_uuid)
    linked_policy_uuids = {p['policy_uuid'] for p in linked_policies_result['data']}
    available_policies = [p for p in policies if p['uuid'] not in linked_policy_uuids]

    return render_template('admin/manage_tags/add_policy.html',
                           tag_info=tag_info,
                           policies=available_policies)

@admin.route('/manage_tags/<tag_uuid>/policies/delete', methods=['POST'])
@admin_required
def delete_tag_policy(tag_uuid):
    selected_tag_policies = request.form.getlist('tag_policies')
    successful_deletions = 0
    failed_deletions = []

    for tp_uuid in selected_tag_policies:
        result = write_delete_tag_policy(tp_uuid)
        if result['status'] == '200':
            successful_deletions += 1
        else:
            failed_deletions.append(result['message'])
    
    if successful_deletions > 0:
        flash(f'Successfully unlinked {successful_deletions} policy{"s" if successful_deletions != 1 else ""} from tag!', 'success')
    
    for error in failed_deletions:
        flash(f'Failed to unlink policy: {error}', 'error')
        
    return redirect(url_for('admin.manage_tag_policies', tag_uuid=tag_uuid))

@admin.route('/confirm_tag_policy_assignment', methods=['GET', 'POST'])
@admin_required
def confirm_tag_policy_assignment():
    newly_added_users_uuids = session.pop('newly_added_users', None)
    tag_uuid = session.pop('current_tag_uuid', None)

    if not newly_added_users_uuids or not tag_uuid:
        flash('No users or tag information found for policy assignment confirmation.', 'error')
        return redirect(url_for('admin.manage_tags'))

    tag_info_result = read_get_tag(uuid=tag_uuid)
    if tag_info_result['status'] != '200':
        flash('Tag not found.', 'error')
        return redirect(url_for('admin.manage_tags'))
    tag_info = tag_info_result['data']

    users_to_assign = []
    for user_uuid in newly_added_users_uuids:
        user_result = read_get_user(uuid=user_uuid)
        if user_result['status'] == '200':
            users_to_assign.append(user_result['data'])

    if not users_to_assign:
        flash('No valid users found for policy assignment.', 'error')
        return redirect(url_for('admin.manage_tags'))

    tag_policies_result = read_get_tag_policies_with_details(tag_uuid)
    tag_policies = tag_policies_result['data'] if tag_policies_result['status'] == '200' else []

    if request.method == 'POST':
        successful_assignments = 0
        failed_assignments = []

        for user_data in users_to_assign:
            user_uuid = user_data['uuid']
            for policy_data in tag_policies:
                policy_uuid = policy_data['policy_uuid']
                due_date_str = request.form.get(f'due_date_{policy_uuid}')
                if due_date_str:
                    due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
                    today = date.today()
                    timeframe_days = (due_date - today).days
                else:
                    timeframe_days = policy_data['timeframe_days']
                assign_policy = request.form.get(f'assign_{policy_uuid}') == 'on'

                if assign_policy:
                    result = write_create_assignment(user_uuid, policy_uuid, timeframe_days)
                    if result['status'] == '201':
                        successful_assignments += 1
                    else:
                        failed_assignments.append({
                            'user_name': user_data['name'],
                            'policy_name': policy_data['policy_name'],
                            'error': result['message']
                        })
        
        if successful_assignments > 0:
            flash(f'Successfully created {successful_assignments} new assignment{"s" if successful_assignments != 1 else ""}!', 'success')
        
        for failure in failed_assignments:
            flash(f'''Failed to assign policy "{failure['policy_name']}" to {failure['user_name']}: {failure['error']}''', 'error')

        return redirect(url_for('admin.manage_tags'))

    return render_template('admin/manage_tags/confirm_policy_assignment.html',
                           tag_info=tag_info,
                           users_to_assign=users_to_assign,
                           tag_policies=tag_policies)

@admin.route('/manage_policies', methods=['GET'])
@admin_required
def manage_policies():
    policies = read_get_policies()
    return render_template('admin/manage_policies/hub.html', policies=policies["data"])

@admin.route('/manage_policies/<policy_uuid>', methods=['GET', 'POST'])
@admin_required
def manage_single_policy(policy_uuid):
    policy_result = read_get_policy(uuid=policy_uuid)
    if policy_result['status'] != '200':
        flash('Policy not found.', 'error')
        return redirect(url_for('admin.manage_policies'))
    policy_info = policy_result['data']

    if request.method == 'POST':
        # Update policy details
        new_name = request.form.get('name', '').strip()
        new_description = request.form.get('description', '').strip()
        new_pdf_link = request.form.get('pdf_link', '').strip()

        if new_name or new_description or new_pdf_link:
            final_name = new_name if new_name else policy_info['name']
            final_description = new_description if new_description else policy_info['description']
            final_pdf_link = new_pdf_link if new_pdf_link else policy_info['pdf_link']
            
            update_result = write_edit_policy(policy_uuid, final_name, final_description, final_pdf_link)
            if update_result['status'] != '200':
                flash(f"Failed to update policy details: {update_result['message']}", 'error')

        # Process assignment removals
        for key, value in request.form.items():
            if key.startswith('remove_assignment_'):
                assignment_uuid = value
                result = write_delete_assignment(assignment_uuid)
                if result['status'] != '200':
                    flash(f"Failed to remove assignment: {result['message']}", 'error')

        # Process new assignments
        new_user_uuids = request.form.getlist('new_assignment_user_uuid')
        for i, user_uuid in enumerate(new_user_uuids):
            due_date_str = request.form.get(f'new_assignment_due_date_{i}')
            if user_uuid and due_date_str:
                due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
                today = date.today()
                timeframe_days = (due_date - today).days
                result = write_create_assignment(user_uuid, policy_uuid, timeframe_days)
                if result['status'] != '201':
                    user_info = read_get_user(uuid=user_uuid)
                    user_name = user_info['data']['name'] if user_info['status'] == '200' else 'Unknown User'
                    flash(f"Failed to assign policy to {user_name}: {result['message']}", 'error')

        # Process tag linking
        new_tag_uuid = request.form.get('new_tag_to_link')
        if new_tag_uuid:
            timeframe_days = request.form.get('new_tag_link_timeframe', 30) # Default to 30 days
            link_result = write_create_tag_policy(new_tag_uuid, policy_uuid, int(timeframe_days))
            if link_result['status'] != '201':
                tag_info = read_get_tag(uuid=new_tag_uuid)
                tag_name = tag_info['data']['name'] if tag_info['status'] == '200' else 'Unknown Tag'
                flash(f"Failed to link policy to tag {tag_name}: {link_result['message']}", 'error')

        # Process tag unlinking
        for key, value in request.form.items():
            if key.startswith('unlink_tag_policy_'):
                tag_policy_uuid = value
                result = write_delete_tag_policy(tag_policy_uuid)
                if result['status'] != '200':
                    flash(f"Failed to unlink policy from tag: {result['message']}", 'error')

        flash('Policy details updated successfully!', 'success')
        return redirect(url_for('admin.manage_single_policy', policy_uuid=policy_uuid))

    # GET request: Fetch all necessary data for the single policy view
    policy_assignments_result = get_assignments_by_policy(policy_uuid)
    policy_info['assignments'] = policy_assignments_result['data'] if policy_assignments_result['status'] == '200' else []

    # Get details for each assignment (user name, policy name, status)
    for assignment in policy_info['assignments']:
        user_info = read_get_user(uuid=assignment['user'])
        assignment['user_name'] = user_info['data']['name'] if user_info['status'] == '200' else 'Unknown User'
        assignment['policy_name'] = policy_info['name'] # Already have policy name
        
        # Determine status (similar to dashboard logic)
        current_time = int(time())
        if assignment['completed_at']:
            assignment['status'] = 'completed'
        elif (assignment['assigned_at'] + assignment['timeframe_seconds']) < current_time:
            assignment['status'] = 'overdue'
        else:
            assignment['status'] = 'pending'

    all_users_result = read_get_users()
    all_users = all_users_result['data'] if all_users_result['status'] == '200' else []

    # Filter out users already assigned to this policy
    assigned_user_uuids = {a['user'] for a in policy_info['assignments']}
    available_users = [u for u in all_users if u['uuid'] not in assigned_user_uuids]

    # Get linked tags for this policy
    linked_tags_result = read_get_tag_policies_with_details(tag_uuid=None) # Need to modify this to get by policy_uuid
    # For now, let's get all tag policies and filter by policy_uuid
    all_tag_policies_result = read_get_tag_policies_with_details(tag_uuid=None) # This function needs to be more generic
    linked_tags = [tp for tp in all_tag_policies_result['data'] if tp['policy_uuid'] == policy_uuid] if all_tag_policies_result['status'] == '200' else []

    # Get all tags and filter out already linked tags
    all_tags_result = read_get_tags()
    all_tags = all_tags_result['data'] if all_tags_result['status'] == '200' else []
    linked_tag_uuids = {lt['tag_uuid'] for lt in linked_tags}
    available_tags = [t for t in all_tags if t['uuid'] not in linked_tag_uuids]

    return render_template('admin/manage_policies/manage_single_policy.html',
                           policy=policy_info,
                           available_users=available_users,
                           available_tags=available_tags,
                           linked_tags=linked_tags)

@admin.route('/manage_policies/create', methods=['GET', 'POST'])
@admin_required
def create_policy():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        pdf_link = request.form['pdf_link']
        policy_creation_result = write_create_policy(name, description, pdf_link)
        if policy_creation_result['status'] == '201':
            new_policy_uuid = policy_creation_result['data']['uuid']
            flash('Policy created successfully! Now assign it to users.', 'success')
            return redirect(url_for('admin.create_assignment', pre_selected_policy=new_policy_uuid))
        else:
            flash(f'Failed to create policy: {policy_creation_result["message"]}', 'error')
            return redirect(url_for('admin.create_policy'))
    return render_template('admin/manage_policies/create.html')


    
@admin.route('/manage_policies/delete', methods=['GET', 'POST'])
@admin_required
def delete_policy():
    if request.method == 'POST':
        selected_policies = request.form.getlist('policies')
        
        successful_deletions = 0
        failed_deletions = []
        total_assignments_deleted = 0
        
        policies_with_counts = get_policies_with_assignment_count()['data']
        policy_map = {p['uuid']: p for p in policies_with_counts}
        
        for policy_uuid in selected_policies:
            if policy_uuid in policy_map:
                total_assignments_deleted += policy_map[policy_uuid].get('assignment_count', 0)
            
            result = write_delete_policy(policy_uuid)
            if result['status'] == '200':
                successful_deletions += 1
            else:
                policy_name = policy_map.get(policy_uuid, {}).get('name', 'Unknown Policy')
                failed_deletions.append({
                    'policy_name': policy_name,
                    'error': result['message']
                })
        
        if successful_deletions > 0:
            message = f'Successfully deleted {successful_deletions} polic{"ies" if successful_deletions != 1 else "y"}'
            if total_assignments_deleted > 0:
                message += f' and {total_assignments_deleted} associated assignment{"s" if total_assignments_deleted != 1 else ""}'
            message += '!'
            flash(message, 'success')
        
        if failed_deletions:
            for failure in failed_deletions:
                flash(f'Failed to delete policy "{failure["policy_name"]}": {failure["error"]}', 'error')
        
        return redirect(url_for('admin.manage_policies'))
    
    policies_result = get_policies_with_assignment_count()
    policies = policies_result['data'] if policies_result['status'] == '200' else []
    
    return render_template('admin/manage_policies/delete.html', policies=policies)

@admin.route('/manage_assignments/delete', methods=['POST'])
@admin_required
def delete_assignment():
    assignment_uuid = request.form.get('assignment_uuid')
    if assignment_uuid:
        result = write_delete_assignment(assignment_uuid)
        if result['status'] == '200':
            flash('Assignment deleted successfully!', 'success')
        else:
            flash(f'Failed to delete assignment: {result["message"]}', 'error')
    else:
        flash('No assignment specified for deletion.', 'error')
    return redirect(url_for('admin.manage_assignments'))

@admin.route('/manage_assignments', methods=['GET'])
@admin_required
def manage_assignments():
    assignments = read_get_pending_assignments()
    return render_template('admin/manage_assignments/hub.html', 
                         assignments=assignments["data"],
                         now=int(time()))



@admin.route('/manage_assignments/create', methods=['GET', 'POST'])
@admin_required
def create_assignment():
    if request.method == 'POST':
        selected_users = request.form.getlist('users')
        policy_uuid = request.form['policy']
        due_date_str = request.form['due_date']
        due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
        today = date.today()
        timeframe_days = (due_date - today).days
        selected_tags = request.form.getlist('selected_tags')

        # Link policy to selected tags
        for tag_uuid in selected_tags:
            link_result = write_create_tag_policy(tag_uuid, policy_uuid, timeframe_days)
            if link_result['status'] == '201':
                flash(f'''Policy linked to tag {read_get_tag(uuid=tag_uuid)['data']['name']} successfully!''', 'info')
            elif link_result['status'] == '409':
                flash(f'''Policy already linked to tag {read_get_tag(uuid=tag_uuid)['data']['name']}.''', 'info')
            else:
                flash(f'''Failed to link policy to tag {read_get_tag(uuid=tag_uuid)['data']['name']}: {link_result['message']}''', 'error')
        
        successful_assignments = 0
        failed_assignments = []
        
        for user_uuid in selected_users:
            result = write_create_assignment(user_uuid, policy_uuid, timeframe_days)
            if result['status'] == '201':
                successful_assignments += 1
            else:
                user_info = read_get_user(uuid=user_uuid)
                user_name = user_info['data']['name'] if user_info['status'] == '200' else 'Unknown User'
                failed_assignments.append({
                    'user_name': user_name,
                    'error': result['message']
                })
        
        if successful_assignments > 0:
            flash(f'Successfully created {successful_assignments} assignment{"s" if successful_assignments != 1 else ""}!', 'success')
        
        if failed_assignments:
            for failure in failed_assignments:
                flash(f'Failed to create assignment for {failure["user_name"]}: {failure["error"]}', 'error')
        
        return redirect(url_for('admin.manage_assignments'))
    
    # Get users with their tags
    users_result = get_users_with_tags()
    users = users_result['data'] if users_result['status'] == '200' else []
    
    policies = read_get_policies()
    tags = read_get_tags()
    assignments = read_get_pending_assignments()
    
    return render_template('admin/manage_assignments/create.html', 
                         users=users, 
                         policies=policies["data"],
                         tags=tags["data"],
                         assignments=assignments["data"])

@admin.route('/manage_users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    if request.method == 'POST':
        # Handle form submission for user management
        # This will involve updating admin status, removing tags, and removing policies
        
        # Process admin status changes
        users_to_update_role = {}
        for key, value in request.form.items():
            if key.startswith('is_admin_'):
                user_uuid = key.replace('is_admin_', '')
                users_to_update_role[user_uuid] = 1 if value == 'on' else 0

        for user_uuid, is_admin_status in users_to_update_role.items():
            # Check if the role actually changed from the initial state
            # To do this, we need the initial state, which should be passed from the frontend
            # For now, we'll just update if the form value is different from current DB state
            # A more robust solution would involve passing initial state from template
            
            # Fetch current user status to prevent unnecessary DB writes and admin demotion issues
            user_result = read_get_user(uuid=user_uuid)
            if user_result['status'] == '200':
                current_is_admin = user_result['data']['is_admin']
                if current_is_admin != is_admin_status:
                    # Prevent demoting the last admin
                    if current_is_admin == 1 and is_admin_status == 0:
                        all_users_result = read_get_users()
                        if all_users_result['status'] == '200':
                            admin_count = sum(1 for u in all_users_result['data'] if u['is_admin'])
                            if admin_count == 1: # This is the last admin
                                flash(f"Cannot demote {user_result['data']['name']}: At least one administrator must remain.", 'error')
                                continue # Skip this user's demotion
                    
                    result = write_update_user_role(user_uuid, is_admin_status)
                    if result['status'] != '200':
                        flash(f"Failed to update role for user {user_result['data']['name']}: {result['message']}", 'error')
            else:
                flash(f"User {user_uuid} not found for role update.", 'error')

        # Process tag removals
        for key, value in request.form.items():
            if key.startswith('remove_tag_'):
                parts = key.split('_')
                user_uuid = parts[2]
                tag_uuid = value # The value is the tag_uuid
                
                result = write_remove_user_from_tag(tag_uuid, user_uuid)
                if result['status'] != '200':
                    # Fetch tag name for better error message
                    tag_info = read_get_tag(uuid=tag_uuid)
                    tag_name = tag_info['data']['name'] if tag_info['status'] == '200' else 'Unknown Tag'
                    flash(f"Failed to remove user {user_uuid} from tag {tag_name}: {result['message']}", 'error')

        # Process policy removals (deleting assignments)
        for key, value in request.form.items():
            if key.startswith('remove_policy_'):
                parts = key.split('_')
                user_uuid = parts[2]
                assignment_uuid = value # The value is the assignment_uuid
                
                result = write_delete_assignment(assignment_uuid)
                if result['status'] != '200':
                    flash(f"Failed to remove policy assignment {assignment_uuid} for user {user_uuid}: {result['message']}", 'error')

        flash('User management changes saved successfully!', 'success')
        return redirect(url_for('admin.manage_users')) # Redirect to GET to show updated state

    # GET request: Display all users with their details
    users_result = get_users_with_tags()
    users = users_result['data'] if users_result['status'] == '200' else []

    # For each user, get their assigned policies
    for user in users:
        assignments_result = get_user_assignments(user['uuid'])
        user['assignments'] = assignments_result['data'] if assignments_result['status'] == '200' else []

    return render_template('admin/manage_users/manage_all.html', users=users)

@admin.route('/manage_users/<user_uuid>', methods=['GET', 'POST'])
@admin_required
def manage_single_user(user_uuid):
    user_result = read_get_user(uuid=user_uuid)
    if user_result['status'] != '200':
        flash('User not found.', 'error')
        return redirect(url_for('admin.manage_users'))
    user_info = user_result['data']

    if request.method == 'POST':
        # Process admin status change
        new_is_admin_status = 1 if request.form.get(f'is_admin_{user_uuid}') == 'on' else 0
        if user_info['is_admin'] != new_is_admin_status:
            if user_info['is_admin'] == 1 and new_is_admin_status == 0:
                all_users_result = read_get_users()
                if all_users_result['status'] == '200':
                    admin_count = sum(1 for u in all_users_result['data'] if u['is_admin'])
                    if admin_count == 1:
                        flash(f"Cannot demote {user_info['name']}: At least one administrator must remain.", 'error')
                    else:
                        write_update_user_role(user_uuid, new_is_admin_status)
            else:
                write_update_user_role(user_uuid, new_is_admin_status)

        # Process tag removals
        for key, value in request.form.items():
            if key.startswith('remove_tag_'):
                tag_uuid = value
                result = write_remove_user_from_tag(tag_uuid, user_uuid)
                if result['status'] != '200':
                    tag_info = read_get_tag(uuid=tag_uuid)
                    tag_name = tag_info['data']['name'] if tag_info['status'] == '200' else 'Unknown Tag'
                    flash(f"Failed to remove user from tag {tag_name}: {result['message']}", 'error')

        # Process assignment removals
        for key, value in request.form.items():
            if key.startswith('remove_assignment_'):
                assignment_uuid = value
                result = write_delete_assignment(assignment_uuid)
                if result['status'] != '200':
                    flash(f"Failed to remove assignment: {result['message']}", 'error')

        # Process new policy assignments
        new_policy_uuids = request.form.getlist('new_policy_uuid')
        for i, policy_uuid in enumerate(new_policy_uuids):
            due_date_str = request.form.get(f'new_policy_due_date_{i}')
            if policy_uuid and due_date_str:
                due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
                today = date.today()
                timeframe_days = (due_date - today).days
                result = write_create_assignment(user_uuid, policy_uuid, timeframe_days)
                if result['status'] != '201':
                    policy_info = read_get_policy(uuid=policy_uuid)
                    policy_name = policy_info['data']['name'] if policy_info['status'] == '200' else 'Unknown Policy'
                    flash(f"Failed to assign policy {policy_name}: {result['message']}", 'error')

        # Process new tag assignments
        new_tag_uuid = request.form.get('new_tag_to_assign')
        if new_tag_uuid:
            add_tag_result = write_add_user_to_tag(new_tag_uuid, user_uuid)
            if add_tag_result['status'] != '200':
                tag_info = read_get_tag(uuid=new_tag_uuid)
                tag_name = tag_info['data']['name'] if tag_info['status'] == '200' else 'Unknown Tag'
                flash(f"Failed to assign tag {tag_name}: {add_tag_result['message']}", 'error')

        flash('User details updated successfully!', 'success')
        return redirect(url_for('admin.manage_single_user', user_uuid=user_uuid))

    # GET request: Fetch all necessary data for the single user view
    user_with_tags_result = get_users_with_tags()
    user_info_with_tags = next((u for u in user_with_tags_result['data'] if u['uuid'] == user_uuid), None)
    if not user_info_with_tags:
        flash('User not found or tags could not be loaded.', 'error')
        return redirect(url_for('admin.manage_users'))

    user_assignments_result = get_user_assignments(user_uuid)
    user_info_with_tags['assignments'] = user_assignments_result['data'] if user_assignments_result['status'] == '200' else []

    all_policies_result = read_get_policies()
    all_policies = all_policies_result['data'] if all_policies_result['status'] == '200' else []

    # Filter out policies already assigned to the user
    assigned_policy_uuids = {a['policy'] for a in user_info_with_tags['assignments']}
    available_policies = [p for p in all_policies if p['uuid'] not in assigned_policy_uuids]

    # Fetch all tags and filter out already assigned tags
    all_tags_result = read_get_tags()
    all_tags = all_tags_result['data'] if all_tags_result['status'] == '200' else []
    
    assigned_tag_uuids = {t['uuid'] for t in user_info_with_tags['tags']}
    available_tags = [t for t in all_tags if t['uuid'] not in assigned_tag_uuids]

    return render_template('admin/manage_users/manage_single_user.html',
                           user=user_info_with_tags,
                           available_policies=available_policies,
                           available_tags=available_tags)



@admin.route('/manage_users/whitelist', methods=['GET', 'POST'])
@admin_required
def whitelist():
    if request.method == 'POST':
        email = request.form.get('email')
        if email:
            result = write_add_to_whitelist(email)
            if result['status'] == '201':
                flash(f'Email "{email}" added to whitelist successfully!', 'success')
            else:
                flash(f'Failed to add email to whitelist: {result["message"]}', 'error')
        return redirect(url_for('admin.whitelist'))

    whitelist_result = read_get_whitelist()
    whitelist = whitelist_result['data'] if whitelist_result['status'] == '200' else []
    return render_template('admin/manage_users/whitelist.html', whitelist=whitelist)

@admin.route('/manage_users/whitelist/remove/<email>', methods=['GET'])
@admin_required
def remove_from_whitelist(email):
    result = write_remove_from_whitelist(email)
    if result['status'] == '200':
        flash(f'Email "{email}" removed from whitelist successfully!', 'success')
    else:
        flash(f'Failed to remove email from whitelist: {result["message"]}', 'error')
    return redirect(url_for('admin.whitelist'))