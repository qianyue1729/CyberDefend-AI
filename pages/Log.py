import streamlit as st
import pandas as pd

st.set_page_config(page_title="Log", page_icon=":bar_chart:", layout="wide")


def app():

    st.title('Log')
    st.write('Welcome to the log.')

    # Load the generated CSV file
    df = pd.read_csv('log_data/log.csv')

    # Add a selectbox to the sidebar for filtering
    status = st.sidebar.selectbox(
        'Select status',
        options=['All'] + list(df['status'].unique())
    )

    prediction = st.sidebar.selectbox(
        'Select type of attack',
        options=['All'] + list(df['prediction'].unique())
    )

    # Filter the data
    if status != 'All':
        df = df[df['status'] == status]
    if prediction != 'All':
        df = df[df['prediction'] == prediction]

    # Initialize the session state
    if 'page_number' not in st.session_state:
        st.session_state.page_number = 0
        st.session_state.prev_status = None
        st.session_state.prev_prediction = None

    # Reset the page number to 0 if a filter is applied
    if (status != st.session_state.prev_status or prediction != st.session_state.prev_prediction):
        st.session_state.page_number = 0
        st.session_state.prev_status = status
        st.session_state.prev_prediction = prediction

    # Add a label to display the current page number
    page_number = st.number_input('Page: ', min_value=0, max_value=len(
        df)//20, value=st.session_state.page_number)
    st.session_state.page_number = page_number

    # Display the data for the current page
    start = st.session_state.page_number * 20
    end = (st.session_state.page_number + 1) * 20
    st.dataframe(df.iloc[start:end], use_container_width=True, height=740)

    *buttons, page_num = st.columns(3)

    with buttons[0]:
        # Add a button to go to the previous page
        if st.button('Previous') and st.session_state.page_number > 0:
            st.session_state.page_number -= 1
    with buttons[1]:
        # Add a button to go to the next page
        if st.button('Next') and end < len(df):
            st.session_state.page_number += 1
    with page_num:
        st.write(f'Page: {st.session_state.page_number + 1}')

    # Download link
    st.markdown(f"Download the data as CSV file [here](fake_data.csv)")


if __name__ == '__main__':
    app()
