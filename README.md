# sf_vote_vis
Makes frames for an animation to visualize voting on Maker stability fee changes
parser and spell fetching all from:
https://github.com/jernejml/mkr_voting
Thank you!


1. change the config.ini file to your node and etherscan api key

2. python3 vote_vis.py --update_spells

3. python3 vote_vis.py --update_voters

4. python3 vote_vis.py --get_interactions

5. python3 vote_vis.py --get_votes_per_frame

6. python3 vote_vis.py --make_frames

7. ffmpeg -r 24 -i 'vote_frame%05d.png' -c:v libx264 -r 24 out.mp4



Notes: You will need access to two different ethereum nodes for this to work. An infura node will not work with --update_voters . I've included the data objects which are up to date as of November 1, 2019. If you just want to build the frames, then you can just do --make frames and not worry about getting up to date data

It might break on the next vote if it includes a SF change and a debt ceiling change. If it breaks for you let me know on the rocketchat

