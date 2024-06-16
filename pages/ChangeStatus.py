import streamlit as st
import pandas as pd
from datetime import datetime
from util import block_ip, allow_ip

st.set_page_config(page_title="Change Status",
                   page_icon=":bar_chart:",
                   layout="wide")

def load_data():
    df = pd.read_csv('log_data/unique.csv')
    ip_dict = dict(zip(df.source_ip, df.status))
    return ip_dict

def change_status(ip, status):
    ip_dict[ip] = status
    date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if status == 'BLOCK':
        # block_ip(ip)
        st.sidebar.write(f'IP {ip} has been blocked.')
    else:
        # allow_ip(ip)
        st.sidebar.write(f'IP {ip} has been allowed.')
    df = pd.read_csv('log_data/unique.csv')
    df.loc[df['source_ip'] == ip, 'status'] = status
    df.loc[df['source_ip'] == ip, 'date'] = date
    df.to_csv('log_data/unique.csv', index=False)

def app():
    global ip_dict

    ip_dict = load_data()

    st.title('Unique Address')
    st.write('Welcome to the unique address.')

    # Create a placeholder for the table
    table_placeholder = st.empty()

    # Display the initial table in the placeholder
    table_placeholder.table(pd.DataFrame(
        list(ip_dict.items()), columns=['source_ip', 'status']))

    selected_ip = st.sidebar.selectbox(
        'Select an IP address to change its status', list(ip_dict.keys()))
    new_status = st.sidebar.selectbox(
        'Select a new status for the IP address', ['ALLOW', 'BLOCK'])
    if st.sidebar.button('Change status'):
        change_status(selected_ip, new_status)
        st.sidebar.write(f'Changed status of {selected_ip} to {new_status}')

        # save the change status to the unique list
        df = pd.DataFrame(list(ip_dict.items()), columns=[
                          'source_ip', 'status'])
        df.to_csv('log_data/unique.csv', index=False)

        # Update the table in the placeholder with the new DataFrame
        table_placeholder.table(df)

if __name__ == '__main__':
    app()